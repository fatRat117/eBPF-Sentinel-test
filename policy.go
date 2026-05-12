package main

import (
	"fmt"
	"log"
	"sync/atomic"

	"github.com/cilium/ebpf"
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
func setExecveMonitoringEnabled(enabled bool) error {
	if err := syncExecveMonitoringMap(enabled); err != nil {
		return err
	}
	execveEnabled.Store(enabled)
	log.Printf("[Policy] Execve monitoring enabled: %v", enabled)
	return nil
}

// isNetworkMonitoringEnabled 检查网络监控是否启用 / Checks whether network monitoring is enabled.
func isNetworkMonitoringEnabled() bool {
	return networkEnabled.Load()
}

// setNetworkMonitoringEnabled 设置网络监控开关 / Updates the network monitoring switch.
func setNetworkMonitoringEnabled(enabled bool) error {
	if err := syncNetworkMonitoringMap(enabled); err != nil {
		return err
	}
	networkEnabled.Store(enabled)
	log.Printf("[Policy] Network monitoring enabled: %v", enabled)
	return nil
}

func syncExecveMonitoringMap(enabled bool) error {
	if execveObjs == nil || execveObjs.MonitoringEnabled == nil {
		return nil
	}
	if err := updateToggleMap(execveObjs.MonitoringEnabled, enabled); err != nil {
		return fmt.Errorf("sync execve monitoring map: %w", err)
	}
	return nil
}

func syncNetworkMonitoringMap(enabled bool) error {
	if networkObjs == nil || networkObjs.NetMonitoringEnabled == nil {
		return nil
	}
	if err := updateToggleMap(networkObjs.NetMonitoringEnabled, enabled); err != nil {
		return fmt.Errorf("sync network monitoring map: %w", err)
	}
	return nil
}

func updateToggleMap(target *ebpf.Map, enabled bool) error {
	var key uint32
	var value uint32
	if enabled {
		value = 1
	}
	return target.Update(key, value, ebpf.UpdateAny)
}
