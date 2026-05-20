package main

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
)

type execPathWhitelistPolicy struct {
	mu       sync.RWMutex
	patterns []string
}

func newExecPathWhitelistPolicy() *execPathWhitelistPolicy {
	return &execPathWhitelistPolicy{}
}

func (p *execPathWhitelistPolicy) ReloadFromDB() error {
	rules, err := models.ListWhitelistRules(models.WhitelistTypeExecPath, false)
	if err != nil {
		return err
	}

	patterns := make([]string, 0, len(rules))
	for _, rule := range rules {
		if value := strings.TrimSpace(rule.Value); value != "" {
			patterns = append(patterns, value)
		}
	}
	p.setPatterns(patterns)
	return nil
}

func (p *execPathWhitelistPolicy) setPatterns(patterns []string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.patterns = append([]string(nil), patterns...)
}

func (p *execPathWhitelistPolicy) Matches(path string) bool {
	if p == nil {
		return false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pattern := range p.patterns {
		if execPathPatternMatches(pattern, path) {
			return true
		}
	}
	return false
}

func markExecveWhitelist(event *plugin.Event, policy *execPathWhitelistPolicy) bool {
	if event == nil || event.Type != "execve" || policy == nil {
		return false
	}
	argv0 := stringFromEventData(event.Data["argv0"])
	if !policy.Matches(argv0) {
		return false
	}
	event.Data["whitelisted"] = true
	return true
}

func execPathPatternMatches(pattern, candidate string) bool {
	pattern = strings.TrimSpace(pattern)
	candidate = strings.TrimSpace(candidate)
	if pattern == "" || candidate == "" {
		return false
	}
	if pattern == candidate {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(candidate, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(candidate, pattern)
	}
	if !strings.Contains(pattern, "/") {
		return filepath.Base(candidate) == pattern
	}
	return false
}

func stringFromEventData(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func normalizeWhitelistType(ruleType string) (string, error) {
	ruleType = strings.TrimSpace(ruleType)
	switch ruleType {
	case models.WhitelistTypeIP, models.WhitelistTypePort, models.WhitelistTypeExecPath:
		return ruleType, nil
	default:
		return "", fmt.Errorf("unsupported whitelist type %q", ruleType)
	}
}

func syncWhitelistRules(networkPlugin *plugin.NetworkPlugin, execPolicy *execPathWhitelistPolicy) error {
	return errors.Join(syncNetworkWhitelistRules(networkPlugin), reloadExecPathWhitelist(execPolicy))
}

func reloadExecPathWhitelist(policy *execPathWhitelistPolicy) error {
	if policy == nil {
		return nil
	}
	return policy.ReloadFromDB()
}

func syncNetworkWhitelistRules(networkPlugin *plugin.NetworkPlugin) error {
	if networkPlugin == nil {
		return nil
	}

	rules, err := models.ListWhitelistRules("", false)
	if err != nil {
		return err
	}

	var result error
	var ips []string
	var ports []uint16
	for _, rule := range rules {
		switch rule.RuleType {
		case models.WhitelistTypeIP:
			ips = append(ips, rule.Value)
		case models.WhitelistTypePort:
			port, err := whitelistPortValue(rule.Value)
			if err != nil {
				result = errors.Join(result, err)
				continue
			}
			ports = append(ports, port)
		}
	}
	result = errors.Join(result, networkPlugin.ReplaceIPWhitelist(ips))
	result = errors.Join(result, networkPlugin.ReplacePortWhitelist(ports))
	return result
}

func createWhitelistRuleConsistent(networkPlugin *plugin.NetworkPlugin, execPolicy *execPathWhitelistPolicy, rule *models.WhitelistRule) error {
	if err := models.CreateWhitelistRule(rule); err != nil {
		return err
	}
	if err := syncWhitelistRules(networkPlugin, execPolicy); err != nil {
		rollbackErr := models.DeleteWhitelistRule(rule.ID)
		resyncErr := syncWhitelistRules(networkPlugin, execPolicy)
		return errors.Join(fmt.Errorf("sync whitelist runtime: %w", err), rollbackErr, resyncErr)
	}
	return nil
}

func updateWhitelistRuleConsistent(networkPlugin *plugin.NetworkPlugin, execPolicy *execPathWhitelistPolicy, oldRule, updatedRule *models.WhitelistRule) error {
	if err := models.UpdateWhitelistRule(updatedRule); err != nil {
		return err
	}
	if err := syncWhitelistRules(networkPlugin, execPolicy); err != nil {
		rollbackErr := models.UpdateWhitelistRule(oldRule)
		resyncErr := syncWhitelistRules(networkPlugin, execPolicy)
		return errors.Join(fmt.Errorf("sync whitelist runtime: %w", err), rollbackErr, resyncErr)
	}
	return nil
}

func deleteWhitelistRuleConsistent(networkPlugin *plugin.NetworkPlugin, execPolicy *execPathWhitelistPolicy, oldRule *models.WhitelistRule) error {
	if err := models.DeleteWhitelistRule(oldRule.ID); err != nil {
		return err
	}
	if err := syncWhitelistRules(networkPlugin, execPolicy); err != nil {
		rollbackErr := models.UpdateWhitelistRule(oldRule)
		resyncErr := syncWhitelistRules(networkPlugin, execPolicy)
		return errors.Join(fmt.Errorf("sync whitelist runtime: %w", err), rollbackErr, resyncErr)
	}
	return nil
}

func normalizeWhitelistRule(ruleType, value string) (string, string, error) {
	var err error
	ruleType, err = normalizeWhitelistType(ruleType)
	if err != nil {
		return "", "", err
	}
	value = strings.TrimSpace(value)
	switch ruleType {
	case models.WhitelistTypeIP:
		ip := net.ParseIP(value).To4()
		if ip == nil {
			return "", "", fmt.Errorf("invalid IPv4 address %q", value)
		}
		return ruleType, ip.String(), nil
	case models.WhitelistTypePort:
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return "", "", fmt.Errorf("invalid port %q", value)
		}
		return ruleType, strconv.FormatUint(port, 10), nil
	case models.WhitelistTypeExecPath:
		if value == "" {
			return "", "", errors.New("exec_path whitelist value is empty")
		}
		if strings.ContainsRune(value, 0) {
			return "", "", errors.New("exec_path whitelist value contains null byte")
		}
		return ruleType, value, nil
	default:
		return "", "", fmt.Errorf("unsupported whitelist type %q", ruleType)
	}
}

func whitelistPortValue(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid whitelist port %q", value)
	}
	return uint16(port), nil
}
