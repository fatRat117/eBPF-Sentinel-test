package main

import (
	"log"

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

	eventChan := make(chan *plugin.Event, 256)
	go dispatchPluginEvents(hub, eventChan)

	cpuUsageFn := startEBPFMonitors(eventChan)
	startSystemPlugin(eventChan, cpuUsageFn)

	log.Println("eBPF Sentinel started! Monitoring execve syscalls, network traffic, and system metrics...")

	r := gin.Default()
	setupRoutes(r, hub)

	log.Println("API server started on :8080")
	log.Println("WebSocket endpoint: ws://localhost:8080/ws")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func dispatchPluginEvents(hub *websocket.Hub, eventChan <-chan *plugin.Event) {
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
		hub.Broadcast(map[string]interface{}{
			"type":      event.Type,
			"timestamp": event.Timestamp,
			"data":      event.Data,
		})
	}
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
	}
}

func startSystemPlugin(eventChan chan<- *plugin.Event, cpuUsageFn func() float64) {
	if cpuUsageFn != nil {
		plugin.GetCPUUsage = cpuUsageFn
		log.Println("[cpu] eBPF CPU monitoring enabled for system plugin")
	}

	systemPlugin := plugin.NewSystemMonitorPlugin()
	if err := systemPlugin.Load(); err != nil {
		log.Printf("[system] Failed to load system plugin: %v", err)
		return
	}
	if err := systemPlugin.Attach(); err != nil {
		log.Printf("[system] Failed to attach system plugin: %v", err)
		return
	}

	go func() {
		if err := systemPlugin.Start(eventChan); err != nil {
			log.Printf("[system] System plugin stopped: %v", err)
		}
	}()
	log.Println("[system] System monitor plugin started")
}
