package main

import (
	"errors"
	"log"
	"sync/atomic"

	"github.com/ebpf-sentinel/internal/plugin"
)

var (
	execvePolicyControl  plugin.PolicyControl
	networkPolicyControl plugin.PolicyControl

	execvePolicyFallback  atomic.Bool
	networkPolicyFallback atomic.Bool
)

func init() {
	execvePolicyFallback.Store(true)
	networkPolicyFallback.Store(true)
}

func setPolicyControls(execveControl plugin.PolicyControl, networkControl plugin.PolicyControl) {
	execvePolicyControl = execveControl
	networkPolicyControl = networkControl
}

// isExecveMonitoringEnabled 检查execve监控是否启用 / Checks whether execve monitoring is enabled.
func isExecveMonitoringEnabled() bool {
	if execvePolicyControl != nil {
		return execvePolicyControl.IsEnabled()
	}
	return execvePolicyFallback.Load()
}

// setExecveMonitoringEnabled 设置execve监控开关 / Updates the execve monitoring switch.
func setExecveMonitoringEnabled(enabled bool) error {
	execvePolicyFallback.Store(enabled)
	if execvePolicyControl == nil {
		return errors.New("execve policy control is not initialized")
	}
	if err := execvePolicyControl.SetEnabled(enabled); err != nil {
		return err
	}
	log.Printf("[Policy] Execve monitoring enabled: %v", enabled)
	return nil
}

// isNetworkMonitoringEnabled 检查网络监控是否启用 / Checks whether network monitoring is enabled.
func isNetworkMonitoringEnabled() bool {
	if networkPolicyControl != nil {
		return networkPolicyControl.IsEnabled()
	}
	return networkPolicyFallback.Load()
}

// setNetworkMonitoringEnabled 设置网络监控开关 / Updates the network monitoring switch.
func setNetworkMonitoringEnabled(enabled bool) error {
	networkPolicyFallback.Store(enabled)
	if networkPolicyControl == nil {
		return errors.New("network policy control is not initialized")
	}
	if err := networkPolicyControl.SetEnabled(enabled); err != nil {
		return err
	}
	log.Printf("[Policy] Network monitoring enabled: %v", enabled)
	return nil
}
