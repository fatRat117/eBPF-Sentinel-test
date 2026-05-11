package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/websocket"
)

var (
	execveObjs   *execveObjects
	networkObjs  *networkObjects
	cpuObjs      *cpuObjects
	execveLinks  []link.Link
	networkLinks []link.Link
	cpuLinks     []link.Link
)

var (
	cpuPrevBusy []uint64
	cpuPrevIdle []uint64
	cpuUsageMu  sync.Mutex
)

// startEBPFMonitors 加载并启动内置eBPF监控 / Starts built-in eBPF monitors and returns CPU usage callback.
func startEBPFMonitors(hub *websocket.Hub) func() float64 {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[warn] failed to remove memlock limit: %v", err)
		log.Println("[warn] eBPF monitoring disabled (requires root)")
	}

	startExecveMonitor(hub)
	startNetworkMonitor(hub)
	if startCPUMonitor() {
		return getCPUUsage
	}
	return nil
}

func startExecveMonitor(hub *websocket.Hub) {
	execveObjs = &execveObjects{}
	if err := loadExecveObjects(execveObjs, nil); err != nil {
		log.Printf("[execve] failed to load execve objects: %v", err)
		log.Println("[execve] execve monitoring disabled (requires root)")
		execveObjs = nil
		return
	}

	execveTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.TracepointExecve, nil)
	if err != nil {
		log.Printf("[execve] failed to attach execve tracepoint: %v", err)
		execveObjs.Close()
		execveObjs = nil
		return
	}
	execveLinks = append(execveLinks, execveTp)

	execveRd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		log.Printf("[execve] failed to open execve ring buffer: %v", err)
		execveTp.Close()
		execveLinks = nil
		execveObjs.Close()
		execveObjs = nil
		return
	}

	go readExecveEvents(execveRd, hub)
}

func readExecveEvents(rd *ringbuf.Reader, hub *websocket.Hub) {
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("[execve] failed to read from ring buffer: %v", err)
			return
		}
		if len(record.RawSample) < execveEventSize {
			continue
		}

		var event execveEvent
		copy((*[execveEventSize]byte)(unsafe.Pointer(&event))[:], record.RawSample[:execveEventSize])

		if !isExecveMonitoringEnabled() {
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		argv0 := string(bytes.Trim(event.Argv0[:], "\x00"))

		dbEvent := &models.ExecveEvent{
			PID:   event.PID,
			PPID:  event.PPID,
			Comm:  comm,
			Argv0: argv0,
		}
		if err := models.CreateEvent(dbEvent); err != nil {
			log.Printf("[execve] failed to save event: %v", err)
		}

		hub.Broadcast(map[string]interface{}{
			"type": "execve",
			"data": map[string]interface{}{
				"pid":   event.PID,
				"ppid":  event.PPID,
				"comm":  comm,
				"argv0": argv0,
			},
		})

		log.Printf("[execve] PID=%d PPID=%d Comm=%s Argv0=%s", event.PID, event.PPID, comm, argv0)
	}
}

func startNetworkMonitor(hub *websocket.Hub) {
	networkObjs = &networkObjects{}
	if err := loadNetworkObjects(networkObjs, nil); err != nil {
		log.Printf("[network] failed to load network objects: %v", err)
		log.Println("[network] Network monitoring disabled")
		networkObjs = nil
		return
	}

	interfaces := getNetworkInterfaces()
	if len(interfaces) == 0 {
		log.Println("[network] No active network interfaces found")
		log.Println("[network] Network monitoring disabled")
		networkObjs.Close()
		networkObjs = nil
		return
	}

	var interfaceNames []string
	for _, iface := range interfaces {
		interfaceNames = append(interfaceNames, iface.Name)
	}
	log.Printf("[network] Found interfaces: %s", strings.Join(interfaceNames, ", "))

	var attachedInterfaces []string
	for _, iface := range interfaces {
		ingressLink, err := attachNetworkProgram(networkObjs, iface.Index, true)
		if err != nil {
			log.Printf("[network] failed to attach ingress to %s: %v", iface.Name, err)
			continue
		}

		egressLink, err := attachNetworkProgram(networkObjs, iface.Index, false)
		if err != nil {
			log.Printf("[network] failed to attach egress to %s: %v", iface.Name, err)
			ingressLink.Close()
			continue
		}

		networkLinks = append(networkLinks, ingressLink, egressLink)
		attachedInterfaces = append(attachedInterfaces, iface.Name)
		log.Printf("[network] Successfully attached to %s", iface.Name)
	}

	if len(attachedInterfaces) == 0 {
		log.Println("[network] Failed to attach to any interface")
		log.Println("[network] Network monitoring disabled")
		networkObjs.Close()
		networkObjs = nil
		return
	}
	log.Printf("[network] Monitoring interfaces: %s", strings.Join(attachedInterfaces, ", "))

	networkRd, err := ringbuf.NewReader(networkObjs.NetEvents)
	if err != nil {
		log.Printf("[network] failed to open network ring buffer: %v", err)
		closeLinks(networkLinks)
		networkLinks = nil
		networkObjs.Close()
		networkObjs = nil
		return
	}

	go readNetworkEvents(networkRd, hub)
}

func readNetworkEvents(rd *ringbuf.Reader, hub *websocket.Hub) {
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("[network] failed to read from ring buffer: %v", err)
			return
		}
		if len(record.RawSample) < networkEventSize {
			continue
		}

		var event networkEvent
		event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
		event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
		event.DstIP = binary.LittleEndian.Uint32(record.RawSample[8:12])
		event.SrcPort = binary.LittleEndian.Uint16(record.RawSample[12:14])
		event.DstPort = binary.LittleEndian.Uint16(record.RawSample[14:16])
		event.Protocol = record.RawSample[16]
		event.Direction = record.RawSample[17]
		event.PacketSize = binary.LittleEndian.Uint32(record.RawSample[18:22])
		copy(event.Comm[:], record.RawSample[22:38])

		if !isNetworkMonitoringEnabled() {
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		srcIP := ipToString(event.SrcIP)
		dstIP := ipToString(event.DstIP)
		proto := protocolToString(event.Protocol)
		direction := "ingress"
		if event.Direction == 1 {
			direction = "egress"
		}

		dbEvent := &models.NetworkEvent{
			PID:        event.PID,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    event.SrcPort,
			DstPort:    event.DstPort,
			Protocol:   event.Protocol,
			Direction:  event.Direction,
			PacketSize: event.PacketSize,
			Comm:       comm,
		}
		if err := models.CreateNetworkEvent(dbEvent); err != nil {
			log.Printf("[network] failed to save event: %v", err)
		}

		hub.Broadcast(map[string]interface{}{
			"type": "network",
			"data": map[string]interface{}{
				"pid":         event.PID,
				"src_ip":      srcIP,
				"dst_ip":      dstIP,
				"src_port":    event.SrcPort,
				"dst_port":    event.DstPort,
				"protocol":    proto,
				"direction":   direction,
				"packet_size": event.PacketSize,
				"comm":        comm,
			},
		})

		log.Printf("[network] %s %s PID=%d %s:%d -> %s:%d (%s) %d bytes",
			direction, proto, event.PID, srcIP, event.SrcPort, dstIP, event.DstPort, comm, event.PacketSize)
	}
}

func startCPUMonitor() bool {
	cpuObjs = &cpuObjects{}
	if err := loadCpuObjects(cpuObjs, nil); err != nil {
		log.Printf("[cpu] failed to load cpu objects: %v", err)
		log.Println("[cpu] CPU monitoring via eBPF disabled, falling back to gopsutil")
		cpuObjs = nil
		return false
	}

	cpuTp, err := link.Tracepoint("sched", "sched_switch", cpuObjs.TracepointSchedSwitch, nil)
	if err != nil {
		log.Printf("[cpu] failed to attach sched_switch tracepoint: %v", err)
		cpuObjs.Close()
		cpuObjs = nil
		return false
	}

	cpuLinks = append(cpuLinks, cpuTp)
	log.Println("[cpu] CPU monitoring eBPF program loaded")
	log.Printf("[cpu] Monitoring %d CPUs via eBPF", runtime.NumCPU())
	return true
}

func getCPUUsage() float64 {
	if cpuObjs == nil || cpuObjs.CpuStats == nil {
		return 0
	}

	cpuUsageMu.Lock()
	defer cpuUsageMu.Unlock()

	var key uint32
	var stats []cpuCpuStat
	if err := cpuObjs.CpuStats.Lookup(key, &stats); err != nil {
		log.Printf("[cpu] failed to lookup cpu stats: %v", err)
		return 0
	}
	if len(stats) == 0 {
		return 0
	}
	if len(cpuPrevBusy) != len(stats) {
		cpuPrevBusy = make([]uint64, len(stats))
		cpuPrevIdle = make([]uint64, len(stats))
	}

	var totalBusy, totalIdle float64
	for i, stat := range stats {
		if stat.BusyNs < cpuPrevBusy[i] || stat.IdleNs < cpuPrevIdle[i] {
			cpuPrevBusy[i] = stat.BusyNs
			cpuPrevIdle[i] = stat.IdleNs
			continue
		}

		totalBusy += float64(stat.BusyNs - cpuPrevBusy[i])
		totalIdle += float64(stat.IdleNs - cpuPrevIdle[i])
		cpuPrevBusy[i] = stat.BusyNs
		cpuPrevIdle[i] = stat.IdleNs
	}

	total := totalBusy + totalIdle
	if total <= 0 {
		return 0
	}
	return (totalBusy / total) * 100
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			l.Close()
		}
	}
}
