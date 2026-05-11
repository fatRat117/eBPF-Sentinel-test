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

	cpuUsageFn := startEBPFMonitors(hub)
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
		hub.Broadcast(map[string]interface{}{
			"type":      event.Type,
			"timestamp": event.Timestamp,
			"data":      event.Data,
		})
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
