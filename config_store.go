package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
)

const (
	configKeyAlert          = "alert_config"
	configKeyExecveEnabled  = "execve_enabled"
	configKeyNetworkEnabled = "network_enabled"
)

var errInvalidAlertConfig = errors.New("invalid alert config")

func loadPersistedRuntimeConfig(alertPlugin *plugin.AlertPlugin) error {
	var result error

	if alertPlugin != nil {
		if value, ok, err := models.GetUserConfig(configKeyAlert); err != nil {
			result = errors.Join(result, fmt.Errorf("load alert config: %w", err))
		} else if ok {
			var config plugin.AlertConfig
			if err := json.Unmarshal([]byte(value), &config); err != nil {
				result = errors.Join(result, fmt.Errorf("parse alert config: %w", err))
			} else if err := alertPlugin.UpdateConfig(config); err != nil {
				result = errors.Join(result, fmt.Errorf("apply alert config: %w", err))
			}
		}
	}

	if value, ok, err := models.GetUserConfig(configKeyExecveEnabled); err != nil {
		result = errors.Join(result, fmt.Errorf("load execve switch: %w", err))
	} else if ok {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("parse execve switch: %w", err))
		} else if err := setExecveMonitoringEnabled(enabled); err != nil {
			result = errors.Join(result, fmt.Errorf("apply execve switch: %w", err))
		}
	}

	if value, ok, err := models.GetUserConfig(configKeyNetworkEnabled); err != nil {
		result = errors.Join(result, fmt.Errorf("load network switch: %w", err))
	} else if ok {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("parse network switch: %w", err))
		} else if err := setNetworkMonitoringEnabled(enabled); err != nil {
			result = errors.Join(result, fmt.Errorf("apply network switch: %w", err))
		}
	}

	if result != nil {
		log.Printf("[Config] persisted runtime config applied with errors: %v", result)
	}
	return result
}

func persistAlertConfig(config plugin.AlertConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return models.UpsertUserConfig(configKeyAlert, string(data))
}

func persistExecveMonitoringEnabled(enabled bool) error {
	return models.UpsertUserConfig(configKeyExecveEnabled, strconv.FormatBool(enabled))
}

func persistNetworkMonitoringEnabled(enabled bool) error {
	return models.UpsertUserConfig(configKeyNetworkEnabled, strconv.FormatBool(enabled))
}

func updateAlertConfigConsistent(alertPlugin *plugin.AlertPlugin, config plugin.AlertConfig) error {
	if alertPlugin == nil {
		return errors.New("alert plugin is not initialized")
	}

	previous := alertPlugin.Config()
	if err := alertPlugin.UpdateConfig(config); err != nil {
		return fmt.Errorf("%w: %v", errInvalidAlertConfig, err)
	}
	current := alertPlugin.Config()
	if err := persistAlertConfig(current); err != nil {
		rollbackErr := alertPlugin.UpdateConfig(previous)
		return errors.Join(fmt.Errorf("persist alert config: %w", err), rollbackErr)
	}
	return nil
}

func updateExecveMonitoringConsistent(enabled bool) error {
	previous := isExecveMonitoringEnabled()
	if err := setExecveMonitoringEnabled(enabled); err != nil {
		return err
	}
	if err := persistExecveMonitoringEnabled(enabled); err != nil {
		rollbackErr := setExecveMonitoringEnabled(previous)
		return errors.Join(fmt.Errorf("persist execve switch: %w", err), rollbackErr)
	}
	return nil
}

func updateNetworkMonitoringConsistent(enabled bool) error {
	previous := isNetworkMonitoringEnabled()
	if err := setNetworkMonitoringEnabled(enabled); err != nil {
		return err
	}
	if err := persistNetworkMonitoringEnabled(enabled); err != nil {
		rollbackErr := setNetworkMonitoringEnabled(previous)
		return errors.Join(fmt.Errorf("persist network switch: %w", err), rollbackErr)
	}
	return nil
}
