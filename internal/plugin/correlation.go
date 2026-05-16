package plugin

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type eventRecord struct {
	PID       uint32                 `json:"pid"`
	PPID      uint32                 `json:"ppid"`
	Comm      string                 `json:"comm"`
	EventType string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

type slidingWindow struct {
	mu         sync.RWMutex
	byPID      map[uint32][]*eventRecord
	windowSize time.Duration
}

func newSlidingWindow(windowSize time.Duration) *slidingWindow {
	return &slidingWindow{
		byPID:      make(map[uint32][]*eventRecord),
		windowSize: windowSize,
	}
}

func (w *slidingWindow) setWindowSize(windowSize time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.windowSize = windowSize
	w.evictExpiredLocked(time.Now())
}

func (w *slidingWindow) push(record *eventRecord) {
	if record == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.byPID[record.PID] = append(w.byPID[record.PID], record)
	w.evictExpiredLocked(record.Timestamp)
}

func (w *slidingWindow) getByPID(pid uint32) []*eventRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return cloneRecords(w.byPID[pid])
}

func (w *slidingWindow) allRecords() []*eventRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var records []*eventRecord
	for _, pidRecords := range w.byPID {
		records = append(records, pidRecords...)
	}
	return cloneRecords(records)
}

func (w *slidingWindow) evictExpiredLocked(now time.Time) {
	if w.windowSize <= 0 {
		return
	}
	cutoff := now.Add(-w.windowSize)
	for pid, records := range w.byPID {
		kept := records[:0]
		for _, record := range records {
			if !record.Timestamp.Before(cutoff) {
				kept = append(kept, record)
			}
		}
		if len(kept) == 0 {
			delete(w.byPID, pid)
			continue
		}
		w.byPID[pid] = kept
	}
}

func cloneRecords(records []*eventRecord) []*eventRecord {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]*eventRecord, len(records))
	copy(cloned, records)
	return cloned
}

type correlationRule interface {
	Name() string
	Match(history []*eventRecord, newEvent *eventRecord) *correlationResult
}

type correlationResult struct {
	RuleID   string
	Severity string
	Message  string
	Details  map[string]interface{}
	Evidence []*eventRecord
}

type reverseShellRule struct {
	maxTimeGap         time.Duration
	suspiciousCommands []string
	suspiciousPorts    map[uint16]string
	window             *slidingWindow
}

func (r reverseShellRule) Name() string {
	return "reverse_shell_detected"
}

func (r reverseShellRule) Match(history []*eventRecord, newEvent *eventRecord) *correlationResult {
	if newEvent == nil {
		return nil
	}

	if newEvent.EventType == "network" && r.isSuspiciousNetworkPort(newEvent) {
		for _, previous := range r.candidateHistory(history) {
			if previous.EventType != "execve" ||
				!r.isSuspiciousCommand(previous) ||
				!r.canRelate(previous, newEvent) ||
				!withinGap(previous, newEvent, r.maxTimeGap) {
				continue
			}
			port, _ := r.suspiciousNetworkPort(newEvent)
			gap := absDuration(newEvent.Timestamp.Sub(previous.Timestamp))
			pid := relatedPID(previous, newEvent)
			return &correlationResult{
				RuleID:   "reverse_shell_detected",
				Severity: "critical",
				Message:  fmt.Sprintf("疑似反弹 Shell：进程 %s(PID=%d) 在执行后 %.1f 秒使用了可疑端口 %d", displayComm(newEvent), pid, gap.Seconds(), port),
				Details: map[string]interface{}{
					"pid":      pid,
					"comm":     displayComm(newEvent),
					"port":     port,
					"src_port": getSrcPort(newEvent.Data),
					"dst_port": getDstPort(newEvent.Data),
				},
				Evidence: chronologicalEvidence(previous, newEvent),
			}
		}
	}

	if newEvent.EventType == "execve" && r.isSuspiciousCommand(newEvent) {
		for _, previous := range history {
			if previous.EventType != "network" ||
				!r.isSuspiciousNetworkPort(previous) ||
				!r.canRelate(newEvent, previous) ||
				!withinGap(previous, newEvent, r.maxTimeGap) {
				continue
			}
			port, _ := r.suspiciousNetworkPort(previous)
			gap := absDuration(newEvent.Timestamp.Sub(previous.Timestamp))
			return &correlationResult{
				RuleID:   "reverse_shell_detected",
				Severity: "critical",
				Message:  fmt.Sprintf("疑似反弹 Shell：进程 %s(PID=%d) 在使用可疑端口 %d 后 %.1f 秒执行", displayComm(newEvent), newEvent.PID, port, gap.Seconds()),
				Details: map[string]interface{}{
					"pid":      newEvent.PID,
					"comm":     displayComm(newEvent),
					"port":     port,
					"src_port": getSrcPort(previous.Data),
					"dst_port": getDstPort(previous.Data),
				},
				Evidence: chronologicalEvidence(previous, newEvent),
			}
		}
	}

	return nil
}

func (r reverseShellRule) isSuspiciousCommand(record *eventRecord) bool {
	comm := strings.ToLower(record.Comm)
	argv0 := strings.ToLower(getArgv0(record.Data))
	for _, command := range r.suspiciousCommands {
		if commandMatches(comm, argv0, command) {
			return true
		}
	}
	return false
}

func (r reverseShellRule) isSuspiciousNetworkPort(record *eventRecord) bool {
	_, ok := r.suspiciousNetworkPort(record)
	return ok
}

func (r reverseShellRule) suspiciousNetworkPort(record *eventRecord) (uint16, bool) {
	if record == nil {
		return 0, false
	}
	if port := getDstPort(record.Data); port != 0 {
		if _, ok := r.suspiciousPorts[port]; ok {
			return port, true
		}
	}
	if port := getSrcPort(record.Data); port != 0 {
		if _, ok := r.suspiciousPorts[port]; ok {
			return port, true
		}
	}
	return 0, false
}

func (r reverseShellRule) candidateHistory(history []*eventRecord) []*eventRecord {
	if r.window == nil {
		return history
	}

	seen := make(map[*eventRecord]bool, len(history))
	candidates := make([]*eventRecord, 0, len(history))
	for _, record := range history {
		seen[record] = true
		candidates = append(candidates, record)
	}
	for _, record := range r.window.allRecords() {
		if !seen[record] {
			candidates = append(candidates, record)
		}
	}
	return candidates
}

func (r reverseShellRule) canRelate(execEvent, networkEvent *eventRecord) bool {
	if execEvent.PID != 0 && execEvent.PID == networkEvent.PID {
		return true
	}
	execComm := strings.ToLower(displayComm(execEvent))
	execArgv0 := strings.ToLower(executableName(getArgv0(execEvent.Data)))
	networkComm := strings.ToLower(displayComm(networkEvent))
	return (execComm != "" && execComm != "unknown" && execComm == networkComm) ||
		(execArgv0 != "" && execArgv0 == networkComm)
}

type dataExfilRule struct {
	maxTimeGap     time.Duration
	sizeThreshold  uint64
	sensitivePaths []string
}

func (r dataExfilRule) Name() string {
	return "data_exfil_detected"
}

func (r dataExfilRule) Match(history []*eventRecord, newEvent *eventRecord) *correlationResult {
	if newEvent == nil || newEvent.EventType != "network" || getDirection(newEvent.Data) != 1 {
		return nil
	}

	size := getNetworkSize(newEvent.Data)
	if size < r.sizeThreshold {
		return nil
	}

	for _, previous := range history {
		if previous.EventType != "execve" || !withinGap(previous, newEvent, r.maxTimeGap) {
			continue
		}
		path := r.sensitivePath(previous)
		if path == "" {
			continue
		}
		gap := absDuration(newEvent.Timestamp.Sub(previous.Timestamp))
		return &correlationResult{
			RuleID:   "data_exfil_detected",
			Severity: "critical",
			Message:  fmt.Sprintf("疑似数据外泄：进程 %s(PID=%d) 读取 %s 后 %.1f 秒上传了 %s 数据", displayComm(newEvent), newEvent.PID, path, gap.Seconds(), formatBytesForAlert(size)),
			Details: map[string]interface{}{
				"pid":        newEvent.PID,
				"comm":       displayComm(newEvent),
				"path":       path,
				"bytes_sent": size,
			},
			Evidence: chronologicalEvidence(previous, newEvent),
		}
	}

	return nil
}

func (r dataExfilRule) sensitivePath(record *eventRecord) string {
	argv0 := strings.ToLower(getArgv0(record.Data))
	for _, path := range r.sensitivePaths {
		if strings.Contains(argv0, strings.ToLower(path)) {
			return path
		}
	}
	return ""
}

type processChainRule struct {
	window   *slidingWindow
	patterns [][]string
}

func (r processChainRule) Name() string {
	return "process_chain_attack"
}

func (r processChainRule) Match(_ []*eventRecord, newEvent *eventRecord) *correlationResult {
	if newEvent == nil || newEvent.EventType != "execve" {
		return nil
	}

	chain := r.buildChain(newEvent)
	if len(chain) == 0 {
		return nil
	}

	names := make([]string, 0, len(chain))
	for _, record := range chain {
		names = append(names, strings.ToLower(record.Comm))
	}

	for _, pattern := range r.patterns {
		if chainMatchesPattern(names, pattern) {
			return &correlationResult{
				RuleID:   "process_chain_attack",
				Severity: "critical",
				Message:  fmt.Sprintf("进程链攻击：%s(PID=%d) 的父进程链 [%s] 匹配攻击模式 [%s]", displayComm(newEvent), newEvent.PID, strings.Join(displayChain(chain), "←"), strings.Join(pattern, ", ")),
				Details: map[string]interface{}{
					"pid":     newEvent.PID,
					"comm":    displayComm(newEvent),
					"chain":   displayChain(chain),
					"pattern": pattern,
				},
				Evidence: chain,
			}
		}
	}

	return nil
}

func (r processChainRule) buildChain(newEvent *eventRecord) []*eventRecord {
	records := r.window.allRecords()
	latestByPID := make(map[uint32]*eventRecord, len(records))
	for _, record := range records {
		if record.EventType != "execve" {
			continue
		}
		if existing, ok := latestByPID[record.PID]; !ok || record.Timestamp.After(existing.Timestamp) {
			latestByPID[record.PID] = record
		}
	}

	chain := []*eventRecord{newEvent}
	seen := map[uint32]bool{newEvent.PID: true}
	for parentPID := newEvent.PPID; parentPID != 0; {
		if seen[parentPID] {
			break
		}
		parent := latestByPID[parentPID]
		if parent == nil {
			break
		}
		chain = append(chain, parent)
		seen[parentPID] = true
		parentPID = parent.PPID
	}

	return chain
}

func eventToRecord(event *Event) *eventRecord {
	if event == nil || event.Type == "alert" {
		return nil
	}
	record := &eventRecord{
		PID:       getPID(event.Data),
		PPID:      getPPID(event.Data),
		Comm:      getComm(event.Data),
		EventType: event.Type,
		Data:      copyEventData(event.Data),
		Timestamp: time.Now(),
	}
	if event.Timestamp > 0 {
		record.Timestamp = time.Unix(event.Timestamp, 0)
	}
	if record.EventType == "system" {
		record.Comm = "kernel"
	}
	if record.Comm == "" {
		record.Comm = "unknown"
	}
	return record
}

func serializeEvidence(records []*eventRecord) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		item := map[string]interface{}{
			"type":      record.EventType,
			"pid":       record.PID,
			"ppid":      record.PPID,
			"comm":      record.Comm,
			"timestamp": record.Timestamp.Unix(),
		}
		for key, value := range record.Data {
			if _, exists := item[key]; !exists {
				item[key] = value
			}
		}
		result = append(result, item)
	}
	return result
}

func getPID(data map[string]interface{}) uint32 {
	value, _ := uint32FromAny(data["pid"])
	return value
}

func getPPID(data map[string]interface{}) uint32 {
	value, _ := uint32FromAny(data["ppid"])
	return value
}

func getComm(data map[string]interface{}) string {
	return stringFromAny(data["comm"])
}

func getArgv0(data map[string]interface{}) string {
	return stringFromAny(data["argv0"])
}

func getDstPort(data map[string]interface{}) uint16 {
	value, _ := uint16FromAny(data["dst_port"])
	return value
}

func getSrcPort(data map[string]interface{}) uint16 {
	value, _ := uint16FromAny(data["src_port"])
	return value
}

func getDirection(data map[string]interface{}) uint8 {
	if value, ok := uint8FromAny(data["direction_id"]); ok {
		return value
	}
	direction := strings.ToLower(stringFromAny(data["direction"]))
	if direction == "egress" || direction == "out" || direction == "outbound" {
		return 1
	}
	return 0
}

func getPacketSize(data map[string]interface{}) uint32 {
	value, _ := uint32FromAny(data["packet_size"])
	return value
}

func getNetworkSize(data map[string]interface{}) uint64 {
	if value, ok := uint64FromAny(data["bytes_sent"]); ok {
		return value
	}
	return uint64(getPacketSize(data))
}

func uint8FromAny(value interface{}) (uint8, bool) {
	switch v := value.(type) {
	case uint8:
		return v, true
	case uint16:
		if v <= math.MaxUint8 {
			return uint8(v), true
		}
	case uint32:
		if v <= math.MaxUint8 {
			return uint8(v), true
		}
	case int:
		if v >= 0 && v <= math.MaxUint8 {
			return uint8(v), true
		}
	case float64:
		if v >= 0 && v <= math.MaxUint8 {
			return uint8(v), true
		}
	}
	return 0, false
}

func uint64FromAny(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case float64:
		if v >= 0 {
			return uint64(v), true
		}
	}
	return 0, false
}

func withinGap(a, b *eventRecord, gap time.Duration) bool {
	if a == nil || b == nil {
		return false
	}
	return absDuration(a.Timestamp.Sub(b.Timestamp)) <= gap
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func chronologicalEvidence(records ...*eventRecord) []*eventRecord {
	result := cloneRecords(records)
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})
	return result
}

func displayComm(record *eventRecord) string {
	if record == nil || record.Comm == "" {
		return "unknown"
	}
	return record.Comm
}

func displayChain(records []*eventRecord) []string {
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, displayComm(record))
	}
	return names
}

func relatedPID(primary, secondary *eventRecord) uint32 {
	if primary != nil && primary.PID != 0 {
		return primary.PID
	}
	if secondary != nil {
		return secondary.PID
	}
	return 0
}

func chainMatchesPattern(chain []string, pattern []string) bool {
	if len(chain) <= len(pattern) {
		return false
	}
	for start := 1; start <= len(chain)-len(pattern); start++ {
		matched := true
		for i := range pattern {
			if chain[start+i] != pattern[len(pattern)-1-i] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func formatBytesForAlert(bytes uint64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}
