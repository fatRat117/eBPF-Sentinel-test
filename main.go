package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
	"github.com/ebpf-sentinel/internal/websocket"
	"github.com/gin-gonic/gin"
)

func main() {
	// 初始化数据库 / Initialize database.
	if _, err := models.InitDB(); err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	log.Println("Database initialized")

	hub := websocket.NewHub()
	go hub.Run()

	manager := plugin.NewManager()
	eventChan := make(chan *plugin.Event, 256)
	go dispatchPluginEvents(hub, manager, eventChan)

	execvePlugin := plugin.NewExecvePlugin(execveBPFProvider{})
	networkPlugin := plugin.NewNetworkPlugin(networkBPFProvider{})
	cpuPlugin := plugin.NewCPUPlugin(cpuBPFProvider{})
	systemPlugin := plugin.NewSystemMonitorPlugin(cpuPlugin.GetCPUUsage)
	alertPlugin := plugin.NewAlertPlugin()

	setPolicyControls(execvePlugin, networkPlugin)
	registerPlugin(manager, execvePlugin)
	registerPlugin(manager, networkPlugin)
	registerPlugin(manager, cpuPlugin)
	registerPlugin(manager, systemPlugin)
	registerPlugin(manager, alertPlugin)

	if err := manager.LoadAll(); err != nil {
		log.Printf("failed to load plugins: %v", err)
	}
	if err := manager.AttachAll(); err != nil {
		log.Printf("failed to attach plugins: %v", err)
	}
	manager.StartAll(eventChan)

	log.Println("eBPF Sentinel started! Monitoring execve syscalls, network traffic, and system metrics...")

	r := gin.Default()
	setupRoutes(r, hub)

	log.Println("API server started on :8080")
	log.Println("WebSocket endpoint: ws://localhost:8080/ws")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func registerPlugin(manager *plugin.Manager, p plugin.Plugin) {
	if err := manager.Register(p); err != nil {
		log.Printf("failed to register plugin %q: %v", p.Name(), err)
	}
}

type execveBPFProvider struct{}

func (execveBPFProvider) LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadExecveObjects(obj, opts)
}

type networkBPFProvider struct{}

func (networkBPFProvider) LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadNetworkObjects(obj, opts)
}

type cpuBPFProvider struct{}

func (cpuBPFProvider) LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadCpuObjects(obj, opts)
}

func dispatchPluginEvents(hub *websocket.Hub, manager *plugin.Manager, eventChan <-chan *plugin.Event) {
	for event := range eventChan {
		// Defense-in-depth: respect policy toggles even if upstream filtering misses.
		switch event.Type {
		case "execve":
			if !isExecveMonitoringEnabled() {
				continue
			}
		case "network":
			if !isNetworkMonitoringEnabled() {
				continue
			}
		}

		persistEvent(event)
		broadcastPluginEvent(hub, event)

		if event.Type == "alert" || manager == nil {
			continue
		}
		for _, observer := range manager.Observers() {
			for _, alert := range observer.HandleEvent(event) {
				if alert == nil {
					continue
				}
				persistEvent(alert)
				broadcastPluginEvent(hub, alert)
			}
		}
	}
}

func broadcastPluginEvent(hub *websocket.Hub, event *plugin.Event) {
	hub.Broadcast(map[string]interface{}{
		"type":      event.Type,
		"timestamp": event.Timestamp,
		"data":      event.Data,
	})
}

func persistEvent(event *plugin.Event) {
	switch event.Type {
	case "execve":
		pid, pidOK := event.Data["pid"].(uint32)
		ppid, ppidOK := event.Data["ppid"].(uint32)
		comm, commOK := event.Data["comm"].(string)
		argv0, argv0OK := event.Data["argv0"].(string)
		if !pidOK || !ppidOK || !commOK || !argv0OK {
			log.Printf("[execve] skipped invalid event payload: %#v", event.Data)
			return
		}
		if err := models.CreateEvent(&models.ExecveEvent{
			PID:   pid,
			PPID:  ppid,
			Comm:  comm,
			Argv0: argv0,
		}); err != nil {
			log.Printf("[execve] failed to save event: %v", err)
		}
	case "network":
		pid, pidOK := event.Data["pid"].(uint32)
		srcIP, srcIPOK := event.Data["src_ip"].(string)
		dstIP, dstIPOK := event.Data["dst_ip"].(string)
		srcPort, srcPortOK := event.Data["src_port"].(uint16)
		dstPort, dstPortOK := event.Data["dst_port"].(uint16)
		protocol, protocolOK := event.Data["protocol_id"].(uint8)
		direction, directionOK := event.Data["direction_id"].(uint8)
		packetSize, packetSizeOK := event.Data["packet_size"].(uint32)
		comm, commOK := event.Data["comm"].(string)
		if !pidOK || !srcIPOK || !dstIPOK || !srcPortOK || !dstPortOK || !protocolOK || !directionOK || !packetSizeOK || !commOK {
			log.Printf("[network] skipped invalid event payload: %#v", event.Data)
			return
		}
		if err := models.CreateNetworkEvent(&models.NetworkEvent{
			PID:        pid,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    srcPort,
			DstPort:    dstPort,
			Protocol:   protocol,
			Direction:  direction,
			PacketSize: packetSize,
			Comm:       comm,
		}); err != nil {
			log.Printf("[network] failed to save event: %v", err)
		}
	case "alert":
		ruleID, ruleOK := event.Data["rule_id"].(string)
		severity, severityOK := event.Data["severity"].(string)
		sourceType, sourceTypeOK := event.Data["source_type"].(string)
		message, messageOK := event.Data["message"].(string)
		if !ruleOK || !severityOK || !sourceTypeOK || !messageOK {
			log.Printf("[alert] skipped invalid event payload: %#v", event.Data)
			return
		}
		if err := models.CreateAlertEvent(&models.AlertEvent{
			RuleID:     ruleID,
			Severity:   severity,
			SourceType: sourceType,
			Message:    message,
			Details:    models.MarshalAlertDetails(event.Data["details"]),
		}); err != nil {
			log.Printf("[alert] failed to save event: %v", err)
		}
	}
}
