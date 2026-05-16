package plugin

import (
	"testing"
	"time"
)

func enableSingleMetricAlerts(t *testing.T, p *AlertPlugin) {
	t.Helper()

	config := p.Config()
	config.SingleMetricAlertsEnabled = true
	if err := p.UpdateConfig(config); err != nil {
		t.Fatalf("enable single metric alerts: %v", err)
	}
}

func TestAlertPluginSensitiveCommand(t *testing.T) {
	p := NewAlertPlugin()
	enableSingleMetricAlerts(t, p)

	alerts := p.HandleEvent(&Event{
		Type: "execve",
		Data: map[string]interface{}{
			"pid":   uint32(100),
			"ppid":  uint32(1),
			"comm":  "chmod",
			"argv0": "/usr/bin/chmod",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Type != "alert" {
		t.Fatalf("expected alert event type, got %q", alerts[0].Type)
	}
	if alerts[0].Data["rule_id"] != "sensitive_command_exec" {
		t.Fatalf("unexpected rule id: %#v", alerts[0].Data["rule_id"])
	}
}

func TestAlertPluginHighCPU(t *testing.T) {
	p := NewAlertPlugin()
	enableSingleMetricAlerts(t, p)

	alerts := p.HandleEvent(&Event{
		Type: "system",
		Data: map[string]interface{}{
			"cpu_usage":     "91.5",
			"net_speed_in":  "0",
			"net_speed_out": "0",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "high_cpu_usage" {
		t.Fatalf("unexpected rule id: %#v", alerts[0].Data["rule_id"])
	}
}

func TestAlertPluginConfigurableMemoryThreshold(t *testing.T) {
	p := NewAlertPlugin()
	if err := p.UpdateConfig(AlertConfig{
		CPUThreshold:              95,
		MemoryThreshold:           50,
		NetSpeedThresholdKB:       2048,
		PacketSizeLimit:           4096,
		CooldownSeconds:           1,
		CorrelationWindowSeconds:  60,
		MaxTimeGapSeconds:         10,
		ExfilSizeThresholdBytes:   1 << 20,
		SingleMetricAlertsEnabled: true,
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}

	alerts := p.HandleEvent(&Event{
		Type: "system",
		Data: map[string]interface{}{
			"cpu_usage":     "10",
			"memory_usage":  "60",
			"net_speed_in":  "0",
			"net_speed_out": "0",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "high_memory_usage" {
		t.Fatalf("unexpected rule id: %#v", alerts[0].Data["rule_id"])
	}
}

func TestAlertPluginCooldown(t *testing.T) {
	p := NewAlertPlugin()
	enableSingleMetricAlerts(t, p)
	event := &Event{
		Type: "execve",
		Data: map[string]interface{}{
			"comm":  "chmod",
			"argv0": "/usr/bin/chmod",
		},
	}

	if alerts := p.HandleEvent(event); len(alerts) != 1 {
		t.Fatalf("expected first event to alert, got %d", len(alerts))
	}
	if alerts := p.HandleEvent(event); len(alerts) != 0 {
		t.Fatalf("expected cooldown to suppress duplicate, got %d", len(alerts))
	}
}

func TestCorrelationReverseShell(t *testing.T) {
	p := NewAlertPlugin()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: time.Now().Add(-1 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(100),
			"ppid":  uint32(1),
			"comm":  "nc",
			"argv0": "/usr/bin/nc",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(100),
			"dst_port":     uint16(4444),
			"direction_id": uint8(1),
			"packet_size":  uint32(64),
			"comm":         "nc",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 correlation alert, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "reverse_shell_detected" {
		t.Fatalf("unexpected rule: %v", alerts[0].Data["rule_id"])
	}
	if alerts[0].Data["severity"] != "critical" {
		t.Fatalf("expected critical severity, got %v", alerts[0].Data["severity"])
	}
	if evidence, ok := alerts[0].Data["evidence"].([]map[string]interface{}); !ok || len(evidence) != 2 {
		t.Fatalf("expected evidence chain, got %#v", alerts[0].Data["evidence"])
	}
}

func TestCorrelationReverseShellAcrossPIDsByComm(t *testing.T) {
	p := NewAlertPlugin()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: time.Now().Add(-1 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(1000),
			"ppid":  uint32(1),
			"comm":  "ncat",
			"argv0": "/usr/bin/ncat",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(0),
			"dst_port":     uint16(4444),
			"direction_id": uint8(1),
			"packet_size":  uint32(64),
			"comm":         "ncat",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected cross-pid reverse shell alert, got %d", len(alerts))
	}
	details, ok := alerts[0].Data["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected details map, got %#v", alerts[0].Data["details"])
	}
	if details["pid"] != uint32(1000) {
		t.Fatalf("expected alert pid from exec event, got %#v", details["pid"])
	}
}

func TestCorrelationReverseShellListeningPort(t *testing.T) {
	p := NewAlertPlugin()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: time.Now().Add(-30 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(1000),
			"ppid":  uint32(1),
			"comm":  "ncat",
			"argv0": "ncat -l 4444",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(1000),
			"src_port":     uint16(4444),
			"dst_port":     uint16(53000),
			"direction_id": uint8(1),
			"packet_size":  uint32(64),
			"comm":         "ncat",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected listening-port reverse shell alert, got %d", len(alerts))
	}
	details, ok := alerts[0].Data["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected details map, got %#v", alerts[0].Data["details"])
	}
	if details["port"] != uint16(4444) {
		t.Fatalf("expected suspicious source port in details, got %#v", details["port"])
	}
}

func TestCorrelationReverseShellExecvePathFromShell(t *testing.T) {
	p := NewAlertPlugin()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: time.Now().Add(-1 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(2000),
			"ppid":  uint32(100),
			"comm":  "bash",
			"argv0": "/usr/bin/ncat",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(2000),
			"src_port":     uint16(4444),
			"dst_port":     uint16(53000),
			"direction_id": uint8(1),
			"packet_size":  uint32(64),
			"comm":         "ncat",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected reverse shell alert for shell execve path, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "reverse_shell_detected" {
		t.Fatalf("unexpected rule: %v", alerts[0].Data["rule_id"])
	}
}

func TestCorrelationReverseShellExecvePathAcrossPIDs(t *testing.T) {
	p := NewAlertPlugin()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: time.Now().Add(-1 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(2001),
			"ppid":  uint32(100),
			"comm":  "bash",
			"argv0": "/usr/bin/ncat",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(0),
			"dst_port":     uint16(4444),
			"direction_id": uint8(1),
			"packet_size":  uint32(64),
			"comm":         "ncat",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected cross-pid reverse shell alert from argv0 executable name, got %d", len(alerts))
	}
}

func TestCorrelationNoFalsePositive(t *testing.T) {
	p := NewAlertPlugin()

	alerts := p.HandleEvent(&Event{
		Type: "execve",
		Data: map[string]interface{}{
			"pid":   uint32(200),
			"ppid":  uint32(1),
			"comm":  "nc",
			"argv0": "/usr/bin/nc",
		},
	})
	if len(alerts) != 0 {
		t.Fatalf("expected no alert for lone execve, got %d", len(alerts))
	}

	alerts = p.HandleEvent(&Event{
		Type: "network",
		Data: map[string]interface{}{
			"pid":          uint32(300),
			"dst_port":     uint16(4444),
			"direction_id": uint8(1),
			"comm":         "unknown",
		},
	})
	if len(alerts) != 0 {
		t.Fatalf("expected no alert for lone network, got %d", len(alerts))
	}
}

func TestCorrelationCooldown(t *testing.T) {
	p := NewAlertPlugin()

	scenario := func(pid uint32) []*Event {
		p.HandleEvent(&Event{
			Type:      "execve",
			Timestamp: time.Now().Add(-1 * time.Second).Unix(),
			Data: map[string]interface{}{
				"pid":   pid,
				"ppid":  uint32(1),
				"comm":  "nc",
				"argv0": "/usr/bin/nc",
			},
		})
		return p.HandleEvent(&Event{
			Type:      "network",
			Timestamp: time.Now().Unix(),
			Data: map[string]interface{}{
				"pid":          pid,
				"dst_port":     uint16(4444),
				"direction_id": uint8(1),
				"comm":         "nc",
			},
		})
	}

	if alerts := scenario(400); len(alerts) != 1 {
		t.Fatalf("expected first alert, got %d", len(alerts))
	}
	if alerts := scenario(400); len(alerts) != 0 {
		t.Fatalf("expected cooldown suppression, got %d", len(alerts))
	}
	if alerts := scenario(401); len(alerts) != 1 {
		t.Fatalf("expected alert for different PID, got %d", len(alerts))
	}
}

func TestProcessChainAttack(t *testing.T) {
	p := NewAlertPlugin()
	now := time.Now()

	events := []*Event{
		{
			Type:      "execve",
			Timestamp: now.Add(-3 * time.Second).Unix(),
			Data:      map[string]interface{}{"pid": uint32(10), "ppid": uint32(1), "comm": "bash", "argv0": "/bin/bash"},
		},
		{
			Type:      "execve",
			Timestamp: now.Add(-2 * time.Second).Unix(),
			Data:      map[string]interface{}{"pid": uint32(11), "ppid": uint32(10), "comm": "python", "argv0": "python exploit.py"},
		},
		{
			Type:      "execve",
			Timestamp: now.Add(-1 * time.Second).Unix(),
			Data:      map[string]interface{}{"pid": uint32(12), "ppid": uint32(11), "comm": "sh", "argv0": "/bin/sh"},
		},
	}
	for _, event := range events {
		if alerts := p.HandleEvent(event); len(alerts) != 0 {
			t.Fatalf("expected no alert before chain completes, got %d", len(alerts))
		}
	}

	alerts := p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: now.Unix(),
		Data:      map[string]interface{}{"pid": uint32(13), "ppid": uint32(12), "comm": "curl", "argv0": "curl http://example"},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected process chain alert, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "process_chain_attack" {
		t.Fatalf("unexpected rule: %v", alerts[0].Data["rule_id"])
	}
}

func TestDataExfil(t *testing.T) {
	p := NewAlertPlugin()
	now := time.Now()

	p.HandleEvent(&Event{
		Type:      "execve",
		Timestamp: now.Add(-5 * time.Second).Unix(),
		Data: map[string]interface{}{
			"pid":   uint32(5678),
			"ppid":  uint32(1),
			"comm":  "cat",
			"argv0": "cat /etc/shadow",
		},
	})

	alerts := p.HandleEvent(&Event{
		Type:      "network",
		Timestamp: now.Unix(),
		Data: map[string]interface{}{
			"pid":          uint32(5678),
			"dst_port":     uint16(443),
			"direction_id": uint8(1),
			"packet_size":  uint32(2 * 1024 * 1024),
			"comm":         "cat",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected data exfil alert, got %d", len(alerts))
	}
	if alerts[0].Data["rule_id"] != "data_exfil_detected" {
		t.Fatalf("unexpected rule: %v", alerts[0].Data["rule_id"])
	}
}
