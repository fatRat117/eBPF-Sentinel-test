package main

import (
	"log"
	"sync/atomic"
)

var (
	execveEnabled  atomic.Bool
	networkEnabled atomic.Bool
)

func init() {
	execveEnabled.Store(true)
	networkEnabled.Store(true)
}

// isExecveMonitoringEnabled 检查execve监控是否启用 / Checks whether execve monitoring is enabled.
func isExecveMonitoringEnabled() bool {
	return execveEnabled.Load()
}

// setExecveMonitoringEnabled 设置execve监控开关 / Updates the execve monitoring switch.
func setExecveMonitoringEnabled(enabled bool) {
	execveEnabled.Store(enabled)
	log.Printf("[Policy] Execve monitoring enabled: %v", enabled)
}

// isNetworkMonitoringEnabled 检查网络监控是否启用 / Checks whether network monitoring is enabled.
func isNetworkMonitoringEnabled() bool {
	return networkEnabled.Load()
}

// setNetworkMonitoringEnabled 设置网络监控开关 / Updates the network monitoring switch.
func setNetworkMonitoringEnabled(enabled bool) {
	networkEnabled.Store(enabled)
	log.Printf("[Policy] Network monitoring enabled: %v", enabled)
}
