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
	defaultMemoryThreshold    = 90.0
	defaultNetSpeedThreshold  = 10240.0 // KB/s
	defaultPacketSizeLimit    = 1 << 20 // bytes
	defaultCorrelationWindow  = 60 * time.Second
	defaultMaxTimeGap         = 60 * time.Second
	defaultExfilTimeGap       = 30 * time.Second
	defaultExfilSizeThreshold = 1 << 20 // bytes
	defaultSuspiciousSeverity = "medium"
)

// AlertConfig contains user-tunable thresholds used by AlertPlugin.
type AlertConfig struct {
	CPUThreshold              float64 `json:"cpu_threshold"`
	MemoryThreshold           float64 `json:"memory_threshold"`
	NetSpeedThresholdKB       float64 `json:"net_speed_threshold_kb"`
	PacketSizeLimit           uint32  `json:"packet_size_limit"`
	CooldownSeconds           int64   `json:"cooldown_seconds"`
	CorrelationWindowSeconds  int64   `json:"correlation_window_seconds"`
	MaxTimeGapSeconds         int64   `json:"max_time_gap_seconds"`
	ExfilSizeThresholdBytes   uint64  `json:"exfil_size_threshold_bytes"`
	SingleMetricAlertsEnabled bool    `json:"single_metric_alerts_enabled"`
}

// AlertPlugin derives alert events from the shared plugin event stream.
type AlertPlugin struct {
	BasePlugin
	mu                    sync.Mutex
	lastAlertByRuleKey    map[string]time.Time
	cooldown              time.Duration
	cpuThreshold          float64
	memoryThreshold       float64
	netSpeedThresholdKB   float64
	packetSizeLimit       uint32
	sensitiveCommands     []string
	suspiciousPorts       map[uint16]string
	window                *slidingWindow
	correlationRules      []correlationRule
	singleMetricEnabled   bool
	correlationWindowSize time.Duration
	maxTimeGap            time.Duration
	exfilSizeThreshold    uint64
}

func NewAlertPlugin() *AlertPlugin {
	p := &AlertPlugin{
		BasePlugin: BasePlugin{
			Name_:        "alert",
			Description_: "Derive security and health alerts from collected events",
		},
		lastAlertByRuleKey:    make(map[string]time.Time),
		cooldown:              defaultAlertCooldown,
		cpuThreshold:          defaultCPUThreshold,
		memoryThreshold:       defaultMemoryThreshold,
		netSpeedThresholdKB:   defaultNetSpeedThreshold,
		packetSizeLimit:       defaultPacketSizeLimit,
		correlationWindowSize: defaultCorrelationWindow,
		maxTimeGap:            defaultMaxTimeGap,
		exfilSizeThreshold:    defaultExfilSizeThreshold,
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
	p.window = newSlidingWindow(p.correlationWindowSize)
	p.correlationRules = p.buildCorrelationRules()
	return p
}

func (p *AlertPlugin) Config() AlertConfig {
	p.mu.Lock()
	defer p.mu.Unlock()

	return AlertConfig{
		CPUThreshold:              p.cpuThreshold,
		MemoryThreshold:           p.memoryThreshold,
		NetSpeedThresholdKB:       p.netSpeedThresholdKB,
		PacketSizeLimit:           p.packetSizeLimit,
		CooldownSeconds:           int64(p.cooldown.Seconds()),
		CorrelationWindowSeconds:  int64(p.correlationWindowSize.Seconds()),
		MaxTimeGapSeconds:         int64(p.maxTimeGap.Seconds()),
		ExfilSizeThresholdBytes:   p.exfilSizeThreshold,
		SingleMetricAlertsEnabled: p.singleMetricEnabled,
	}
}

func (p *AlertPlugin) UpdateConfig(config AlertConfig) error {
	config = p.fillConfigDefaults(config)
	// 处理边界
	if config.CPUThreshold <= 0 || config.CPUThreshold > 100 {
		return fmt.Errorf("cpu_threshold must be between 0 and 100")
	}
	if config.MemoryThreshold <= 0 || config.MemoryThreshold > 100 {
		return fmt.Errorf("memory_threshold must be between 0 and 100")
	}
	if config.NetSpeedThresholdKB <= 0 {
		return fmt.Errorf("net_speed_threshold_kb must be greater than 0")
	}
	if config.PacketSizeLimit == 0 {
		return fmt.Errorf("packet_size_limit must be greater than 0")
	}
	if config.CooldownSeconds <= 0 {
		return fmt.Errorf("cooldown_seconds must be greater than 0")
	}
	if config.CorrelationWindowSeconds <= 0 {
		return fmt.Errorf("correlation_window_seconds must be greater than 0")
	}
	if config.MaxTimeGapSeconds <= 0 {
		return fmt.Errorf("max_time_gap_seconds must be greater than 0")
	}
	if config.ExfilSizeThresholdBytes == 0 {
		return fmt.Errorf("exfil_size_threshold_bytes must be greater than 0")
	}

	p.mu.Lock()

	// 更新阈值
	p.cpuThreshold = config.CPUThreshold
	p.memoryThreshold = config.MemoryThreshold
	p.netSpeedThresholdKB = config.NetSpeedThresholdKB
	p.packetSizeLimit = config.PacketSizeLimit
	p.cooldown = time.Duration(config.CooldownSeconds) * time.Second
	p.correlationWindowSize = time.Duration(config.CorrelationWindowSeconds) * time.Second
	p.maxTimeGap = time.Duration(config.MaxTimeGapSeconds) * time.Second
	p.exfilSizeThreshold = config.ExfilSizeThresholdBytes
	p.singleMetricEnabled = config.SingleMetricAlertsEnabled
	p.correlationRules = p.buildCorrelationRules()
	p.lastAlertByRuleKey = make(map[string]time.Time)
	window := p.window
	windowSize := p.correlationWindowSize
	p.mu.Unlock()

	if window != nil {
		window.setWindowSize(windowSize)
	}
	return nil
}

func (p *AlertPlugin) fillConfigDefaults(config AlertConfig) AlertConfig {
	current := p.Config()
	if config.CPUThreshold == 0 {
		config.CPUThreshold = current.CPUThreshold
	}
	if config.MemoryThreshold == 0 {
		config.MemoryThreshold = current.MemoryThreshold
	}
	if config.NetSpeedThresholdKB == 0 {
		config.NetSpeedThresholdKB = current.NetSpeedThresholdKB
	}
	if config.PacketSizeLimit == 0 {
		config.PacketSizeLimit = current.PacketSizeLimit
	}
	if config.CooldownSeconds == 0 {
		config.CooldownSeconds = current.CooldownSeconds
	}
	if config.CorrelationWindowSeconds == 0 {
		config.CorrelationWindowSeconds = current.CorrelationWindowSeconds
	}
	if config.MaxTimeGapSeconds == 0 {
		config.MaxTimeGapSeconds = current.MaxTimeGapSeconds
	}
	if config.ExfilSizeThresholdBytes == 0 {
		config.ExfilSizeThresholdBytes = current.ExfilSizeThresholdBytes
	}
	return config
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

	record := eventToRecord(event)
	if record == nil {
		return nil
	}
	p.window.push(record)

	history := p.window.getByPID(record.PID)
	rules, singleMetricEnabled := p.observerConfig()
	var alerts []*Event
	for _, rule := range rules {
		result := rule.Match(history, record)
		if result == nil {
			continue
		}
		if !p.allow(result.RuleID + ":" + strconv.FormatUint(uint64(alertPID(result, record)), 10)) {
			continue
		}
		alerts = append(alerts, p.buildAlertEvent(result, record))
	}

	if singleMetricEnabled {
		alerts = append(alerts, p.handleSingleMetric(event)...)
	}

	return compactAlerts(alerts)
}

func (p *AlertPlugin) observerConfig() ([]correlationRule, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	rules := make([]correlationRule, len(p.correlationRules))
	copy(rules, p.correlationRules)
	return rules, p.singleMetricEnabled
}

func (p *AlertPlugin) buildCorrelationRules() []correlationRule {
	return []correlationRule{
		reverseShellRule{
			maxTimeGap:         p.maxTimeGap,
			suspiciousCommands: append([]string(nil), p.sensitiveCommands...),
			suspiciousPorts:    copySuspiciousPorts(p.suspiciousPorts),
			window:             p.window,
		},
		dataExfilRule{
			maxTimeGap:    defaultExfilTimeGap,
			sizeThreshold: p.exfilSizeThreshold,
			sensitivePaths: []string{
				"/etc/shadow",
				"/etc/passwd",
				"/root/.ssh",
				"/etc/ssl/private",
				"~/.aws/credentials",
			},
		},
		processChainRule{
			window: p.window,
			patterns: [][]string{
				{"bash", "python", "sh"},
				{"bash", "python3", "sh"},
				{"java", "bash", "curl"},
				{"php", "sh", "wget"},
			},
		},
	}
}

func (p *AlertPlugin) buildAlertEvent(result *correlationResult, record *eventRecord) *Event {
	details := copyEventData(result.Details)
	if _, ok := details["pid"]; !ok && record != nil {
		details["pid"] = record.PID
	}
	if _, ok := details["comm"]; !ok && record != nil {
		details["comm"] = record.Comm
	}

	return &Event{
		Type:      "alert",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"rule_id":     result.RuleID,
			"severity":    result.Severity,
			"source_type": sourceTypeFromEvidence(result.Evidence, record),
			"message":     result.Message,
			"details":     details,
			"evidence":    serializeEvidence(result.Evidence),
		},
	}
}

func (p *AlertPlugin) handleSingleMetric(event *Event) []*Event {
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

	config := p.Config()
	cpuUsage, ok := floatFromAny(event.Data["cpu_usage"])
	if ok && cpuUsage >= config.CPUThreshold {
		alerts = append(alerts, p.newAlert("high_cpu_usage", "warning", event.Type,
			fmt.Sprintf("CPU usage is %.1f%%", cpuUsage),
			map[string]interface{}{"cpu_usage": cpuUsage, "threshold": config.CPUThreshold},
			"system"))
	}

	memoryUsage, ok := floatFromAny(event.Data["memory_usage"])
	if ok && memoryUsage >= config.MemoryThreshold {
		alerts = append(alerts, p.newAlert("high_memory_usage", "warning", event.Type,
			fmt.Sprintf("Memory usage is %.1f%%", memoryUsage),
			map[string]interface{}{"memory_usage": memoryUsage, "threshold": config.MemoryThreshold},
			"system"))
	}

	netSpeedIn, hasIn := floatFromAny(event.Data["net_speed_in"])
	if hasIn && netSpeedIn >= config.NetSpeedThresholdKB {
		alerts = append(alerts, p.newAlert("high_download_speed", "warning", event.Type,
			fmt.Sprintf("Download speed is %.1f KB/s", netSpeedIn),
			map[string]interface{}{"net_speed_in": netSpeedIn, "threshold": config.NetSpeedThresholdKB},
			"network:in"))
	}

	netSpeedOut, hasOut := floatFromAny(event.Data["net_speed_out"])
	if hasOut && netSpeedOut >= config.NetSpeedThresholdKB {
		alerts = append(alerts, p.newAlert("high_upload_speed", "warning", event.Type,
			fmt.Sprintf("Upload speed is %.1f KB/s", netSpeedOut),
			map[string]interface{}{"net_speed_out": netSpeedOut, "threshold": config.NetSpeedThresholdKB},
			"network:out"))
	}

	return compactAlerts(alerts)
}

func copySuspiciousPorts(ports map[uint16]string) map[uint16]string {
	copied := make(map[uint16]string, len(ports))
	for port, label := range ports {
		copied[port] = label
	}
	return copied
}

func sourceTypeFromEvidence(evidence []*eventRecord, fallback *eventRecord) string {
	if len(evidence) > 0 && evidence[len(evidence)-1] != nil {
		return evidence[len(evidence)-1].EventType
	}
	if fallback != nil {
		return fallback.EventType
	}
	return "unknown"
}

func alertPID(result *correlationResult, fallback *eventRecord) uint32 {
	if result != nil {
		if pid, ok := uint32FromAny(result.Details["pid"]); ok {
			return pid
		}
	}
	if fallback != nil {
		return fallback.PID
	}
	return 0
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
	config := p.Config()

	port, label, suspicious := p.suspiciousPortFromEvent(event)
	if suspicious {
		alerts = append(alerts, p.newAlert("suspicious_network_port", defaultSuspiciousSeverity, event.Type,
			fmt.Sprintf("Connection using suspicious port %d (%s)", port, label),
			copyEventData(event.Data),
			fmt.Sprintf("network:port:%d", port)))
	}

	packetSize, ok := uint32FromAny(event.Data["packet_size"])
	if ok && packetSize >= config.PacketSizeLimit {
		alerts = append(alerts, p.newAlert("large_network_packet", "info", event.Type,
			fmt.Sprintf("Large network packet observed: %d bytes", packetSize),
			copyEventData(event.Data),
			"network:large_packet"))
	}

	return compactAlerts(alerts)
}

func (p *AlertPlugin) suspiciousPortFromEvent(event *Event) (uint16, string, bool) {
	if event == nil {
		return 0, "", false
	}
	if dstPort, ok := uint16FromAny(event.Data["dst_port"]); ok {
		if label, suspicious := p.suspiciousPorts[dstPort]; suspicious {
			return dstPort, label, true
		}
	}
	if srcPort, ok := uint16FromAny(event.Data["src_port"]); ok {
		if label, suspicious := p.suspiciousPorts[srcPort]; suspicious {
			return srcPort, label, true
		}
	}
	return 0, "", false
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
	argv0Name := executableName(argv0)
	return comm == command ||
		strings.HasSuffix(comm, "/"+command) ||
		argv0 == command ||
		argv0Name == command ||
		strings.HasSuffix(argv0, "/"+command) ||
		strings.HasPrefix(argv0, command+" ") ||
		strings.HasPrefix(argv0, command+"\x00") ||
		strings.Contains(argv0, "/"+command+" ")
}

func executableName(argv0 string) string {
	if argv0 == "" {
		return ""
	}
	firstField := strings.Fields(argv0)
	if len(firstField) > 0 {
		argv0 = firstField[0]
	}
	argv0 = strings.TrimRight(argv0, "\x00")
	if idx := strings.LastIndex(argv0, "/"); idx >= 0 {
		return argv0[idx+1:]
	}
	return argv0
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
