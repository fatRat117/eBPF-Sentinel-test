package plugin

import "testing"

func TestAlertPluginSensitiveCommand(t *testing.T) {
	p := NewAlertPlugin()

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

func TestAlertPluginCooldown(t *testing.T) {
	p := NewAlertPlugin()
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
