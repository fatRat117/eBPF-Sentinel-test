package main

import (
	"path/filepath"
	"testing"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestExecPathPatternMatches(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		candidate string
		want      bool
	}{
		{name: "exact path", pattern: "/usr/bin/chmod", candidate: "/usr/bin/chmod", want: true},
		{name: "basename", pattern: "chmod", candidate: "/usr/bin/chmod", want: true},
		{name: "directory prefix", pattern: "/usr/local/bin/", candidate: "/usr/local/bin/tool", want: true},
		{name: "star prefix", pattern: "/opt/trusted/*", candidate: "/opt/trusted/agent", want: true},
		{name: "path mismatch", pattern: "/usr/bin/chmod", candidate: "/tmp/chmod", want: false},
		{name: "basename mismatch", pattern: "curl", candidate: "/usr/bin/chmod", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := execPathPatternMatches(tt.pattern, tt.candidate); got != tt.want {
				t.Fatalf("execPathPatternMatches(%q, %q) = %v, want %v", tt.pattern, tt.candidate, got, tt.want)
			}
		})
	}
}

func TestMarkExecveWhitelistSuppressesByPolicy(t *testing.T) {
	policy := newExecPathWhitelistPolicy()
	policy.setPatterns([]string{"/usr/bin/chmod"})

	event := &plugin.Event{
		Type: "execve",
		Data: map[string]interface{}{
			"argv0": "/usr/bin/chmod",
		},
	}

	if !markExecveWhitelist(event, policy) {
		t.Fatal("expected execve event to match whitelist")
	}
	if event.Data["whitelisted"] != true {
		t.Fatalf("expected event to be marked whitelisted, got %#v", event.Data["whitelisted"])
	}
}

func TestCreateWhitelistRuleConsistentRollsBackOnSyncFailure(t *testing.T) {
	setupWhitelistPolicyTestDB(t)

	rule := &models.WhitelistRule{
		RuleType: models.WhitelistTypePort,
		Value:    "not-a-port",
		Enabled:  true,
	}
	networkPlugin := plugin.NewNetworkPlugin(nil)
	if err := createWhitelistRuleConsistent(networkPlugin, nil, rule); err == nil {
		t.Fatal("expected sync failure for invalid port")
	}

	rules, err := models.ListWhitelistRules("", true)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected failed create to roll back DB row, got %#v", rules)
	}
}

func TestUpdateWhitelistRuleConsistentRollsBackOnSyncFailure(t *testing.T) {
	setupWhitelistPolicyTestDB(t)

	oldRule := &models.WhitelistRule{
		RuleType: models.WhitelistTypePort,
		Value:    "22",
		Enabled:  true,
	}
	if err := models.CreateWhitelistRule(oldRule); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	updated := *oldRule
	updated.Value = "not-a-port"
	networkPlugin := plugin.NewNetworkPlugin(nil)
	if err := updateWhitelistRuleConsistent(networkPlugin, nil, oldRule, &updated); err == nil {
		t.Fatal("expected sync failure for invalid port")
	}

	rule, found, err := models.FindWhitelistRule(models.WhitelistTypePort, "22")
	if err != nil {
		t.Fatalf("find rolled back rule: %v", err)
	}
	if !found || rule.ID != oldRule.ID {
		t.Fatalf("expected old rule after rollback, found=%v rule=%#v", found, rule)
	}
	if _, found, err := models.FindWhitelistRule(models.WhitelistTypePort, "not-a-port"); err != nil || found {
		t.Fatalf("expected invalid updated rule to be removed, found=%v err=%v", found, err)
	}
}

func setupWhitelistPolicyTestDB(t *testing.T) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sentinel-test.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.UserConfig{}, &models.WhitelistRule{}); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	models.DB = db
	t.Cleanup(func() {
		models.DB = nil
	})
}
