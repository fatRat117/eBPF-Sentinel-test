package plugin

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAlertCooldown      = 30 * time.Second
	defaultCPUThreshold       = 85.0
	defaultNetSpeedThreshold  = 10240.0 // KB/s
	defaultPacketSizeLimit    = 1 << 20 // bytes
	defaultSuspiciousSeverity = "medium"
)

// AlertPlugin derives alert events from the shared plugin event stream.
type AlertPlugin struct {
	BasePlugin
	mu                  sync.Mutex
	lastAlertByRuleKey  map[string]time.Time
	cooldown            time.Duration
	cpuThreshold        float64
	netSpeedThresholdKB float64
	packetSizeLimit     uint32
	sensitiveCommands   []string
	suspiciousPorts     map[uint16]string
}

func NewAlertPlugin() *AlertPlugin {
	return &AlertPlugin{
		BasePlugin: BasePlugin{
			Name_:        "alert",
			Description_: "Derive security and health alerts from collected events",
		},
		lastAlertByRuleKey:  make(map[string]time.Time),
		cooldown:            defaultAlertCooldown,
		cpuThreshold:        defaultCPUThreshold,
		netSpeedThresholdKB: defaultNetSpeedThreshold,
		packetSizeLimit:     defaultPacketSizeLimit,
		sensitiveCommands: []string{
			"nc",
			"ncat",
			"netcat",
			"socat",
			"tcpdump",
			"nmap",
			"masscan",
			"chmod",
			"chattr",
		},
		suspiciousPorts: map[uint16]string{
			22:    "ssh",
			23:    "telnet",
			3389:  "rdp",
			4444:  "common reverse shell",
			5555:  "common adb/reverse shell",
			31337: "common backdoor",
		},
	}
}

func (p *AlertPlugin) Load() error {
	return nil
}

func (p *AlertPlugin) Attach() error {
	return nil
}

func (p *AlertPlugin) Detach() error {
	return nil
}

func (p *AlertPlugin) Close() error {
	return nil
}

func (p *AlertPlugin) Start(eventChan chan<- *Event) error {
	return nil
}

func (p *AlertPlugin) HandleEvent(event *Event) []*Event {
	if event == nil || event.Type == "alert" {
		return nil
	}

	switch event.Type {
	case "system":
		return p.handleSystemEvent(event)
	case "execve":
		return p.handleExecveEvent(event)
	case "network":
		return p.handleNetworkEvent(event)
	default:
		return nil
	}
}

func (p *AlertPlugin) handleSystemEvent(event *Event) []*Event {
	var alerts []*Event

	cpuUsage, ok := floatFromAny(event.Data["cpu_usage"])
	if ok && cpuUsage >= p.cpuThreshold {
		alerts = append(alerts, p.newAlert("high_cpu_usage", "warning", event.Type,
			fmt.Sprintf("CPU usage is %.1f%%", cpuUsage),
			map[string]interface{}{"cpu_usage": cpuUsage, "threshold": p.cpuThreshold},
			"system"))
	}

	netSpeedIn, hasIn := floatFromAny(event.Data["net_speed_in"])
	if hasIn && netSpeedIn >= p.netSpeedThresholdKB {
		alerts = append(alerts, p.newAlert("high_download_speed", "warning", event.Type,
			fmt.Sprintf("Download speed is %.1f KB/s", netSpeedIn),
			map[string]interface{}{"net_speed_in": netSpeedIn, "threshold": p.netSpeedThresholdKB},
			"network:in"))
	}

	netSpeedOut, hasOut := floatFromAny(event.Data["net_speed_out"])
	if hasOut && netSpeedOut >= p.netSpeedThresholdKB {
		alerts = append(alerts, p.newAlert("high_upload_speed", "warning", event.Type,
			fmt.Sprintf("Upload speed is %.1f KB/s", netSpeedOut),
			map[string]interface{}{"net_speed_out": netSpeedOut, "threshold": p.netSpeedThresholdKB},
			"network:out"))
	}

	return compactAlerts(alerts)
}

func (p *AlertPlugin) handleExecveEvent(event *Event) []*Event {
	comm := strings.ToLower(stringFromAny(event.Data["comm"]))
	argv0 := strings.ToLower(stringFromAny(event.Data["argv0"]))

	for _, command := range p.sensitiveCommands {
		if commandMatches(comm, argv0, command) {
			return compactAlerts([]*Event{
				p.newAlert("sensitive_command_exec", defaultSuspiciousSeverity, event.Type,
					fmt.Sprintf("Sensitive command executed: %s", command),
					map[string]interface{}{
						"pid":   event.Data["pid"],
						"ppid":  event.Data["ppid"],
						"comm":  event.Data["comm"],
						"argv0": event.Data["argv0"],
					},
					"execve:"+command),
			})
		}
	}

	return nil
}

func (p *AlertPlugin) handleNetworkEvent(event *Event) []*Event {
	var alerts []*Event

	dstPort, ok := uint16FromAny(event.Data["dst_port"])
	if ok {
		if label, suspicious := p.suspiciousPorts[dstPort]; suspicious {
			alerts = append(alerts, p.newAlert("suspicious_network_port", defaultSuspiciousSeverity, event.Type,
				fmt.Sprintf("Connection to suspicious port %d (%s)", dstPort, label),
				copyEventData(event.Data),
				fmt.Sprintf("network:port:%d", dstPort)))
		}
	}

	packetSize, ok := uint32FromAny(event.Data["packet_size"])
	if ok && packetSize >= p.packetSizeLimit {
		alerts = append(alerts, p.newAlert("large_network_packet", "info", event.Type,
			fmt.Sprintf("Large network packet observed: %d bytes", packetSize),
			copyEventData(event.Data),
			"network:large_packet"))
	}

	return compactAlerts(alerts)
}

func (p *AlertPlugin) newAlert(ruleID, severity, sourceType, message string, details map[string]interface{}, keyParts ...string) *Event {
	ruleKey := ruleID + ":" + strings.Join(keyParts, ":")
	if !p.allow(ruleKey) {
		return nil
	}

	return &Event{
		Type:      "alert",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"rule_id":     ruleID,
			"severity":    severity,
			"source_type": sourceType,
			"message":     message,
			"details":     details,
		},
	}
}

func (p *AlertPlugin) allow(ruleKey string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if last, ok := p.lastAlertByRuleKey[ruleKey]; ok && now.Sub(last) < p.cooldown {
		return false
	}
	p.lastAlertByRuleKey[ruleKey] = now
	return true
}

func compactAlerts(alerts []*Event) []*Event {
	result := alerts[:0]
	for _, alert := range alerts {
		if alert != nil {
			result = append(result, alert)
		}
	}
	return result
}

func commandMatches(comm, argv0, command string) bool {
	return comm == command ||
		strings.HasSuffix(comm, "/"+command) ||
		argv0 == command ||
		strings.HasPrefix(argv0, command+" ") ||
		strings.Contains(argv0, "/"+command+" ")
}

func copyEventData(data map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{}, len(data))
	for key, value := range data {
		copied[key] = value
	}
	return copied
}

func stringFromAny(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func floatFromAny(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case string:
		parsed, err := strconv.ParseFloat(v, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func uint16FromAny(value interface{}) (uint16, bool) {
	switch v := value.(type) {
	case uint16:
		return v, true
	case uint32:
		if v <= 65535 {
			return uint16(v), true
		}
	case int:
		if v >= 0 && v <= 65535 {
			return uint16(v), true
		}
	case float64:
		if v >= 0 && v <= 65535 {
			return uint16(v), true
		}
	}
	return 0, false
}

func uint32FromAny(value interface{}) (uint32, bool) {
	switch v := value.(type) {
	case uint32:
		return v, true
	case uint64:
		if v <= 1<<32-1 {
			return uint32(v), true
		}
	case int:
		if v >= 0 {
			return uint32(v), true
		}
	case float64:
		if v >= 0 && v <= 1<<32-1 {
			return uint32(v), true
		}
	}
	return 0, false
}
