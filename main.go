package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
	"github.com/ebpf-sentinel/internal/websocket"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/process"
)

// execveEvent 对应eBPF中的execve事件结构体
// 必须与ebpf/execve.c中的struct event完全匹配
type execveEvent struct {
	PID   uint32    // 进程ID
	PPID  uint32    // 父进程ID
	Comm  [16]byte  // 进程名（固定长度数组）
	Argv0 [128]byte // 命令行参数（固定长度数组）
}

// networkEvent 对应eBPF中的网络事件结构体
// 必须与ebpf/network.c中的struct net_event完全匹配
type networkEvent struct {
	PID        uint32   // 进程ID
	SrcIP      uint32   // 源IP地址（网络字节序）
	DstIP      uint32   // 目的IP地址（网络字节序）
	SrcPort    uint16   // 源端口
	DstPort    uint16   // 目的端口
	Protocol   uint8    // 传输层协议
	Direction  uint8    // 方向：0=入站, 1=出站
	PacketSize uint32   // 数据包大小
	Comm       [16]byte // 进程名
}

// eBPF对象全局实例
// 用于API接口操作BPF Maps
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

// 内存中的策略配置
var (
	execveEnabled  = true
	networkEnabled = true
)


// ipToString 将32位整数IP地址转换为点分十进制字符串
// 注意：eBPF中存储的是网络字节序，这里已经通过bpf_ntohl转换为主机字节序
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}

// protocolToString 将协议号转换为可读字符串
func protocolToString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// getNetworkInterfaces 获取所有活动的网络接口
// 排除回环接口(lo)和未启用的接口
func getNetworkInterfaces() []*net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []*net.Interface
	for i := range ifaces {
		iface := &ifaces[i]
		// 跳过回环接口和未启用的接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface)
	}
	return result
}

// attachNetworkProgram 挂载网络eBPF程序到指定接口
// isIngress: true表示入站程序，false表示出站程序
func attachNetworkProgram(objs *networkObjects, ifaceIdx int, isIngress bool) (link.Link, error) {
	var prog *ebpf.Program
	var attachType ebpf.AttachType

	if isIngress {
		prog = objs.TcIngress
		attachType = ebpf.AttachTCXIngress
	} else {
		prog = objs.TcEgress
		attachType = ebpf.AttachTCXEgress
	}

	// 使用TCX（TC eXpress）API挂载
	// TCX是较新的挂载方式，比传统tc filter更灵活
	tcxOpts := link.TCXOptions{
		Interface: ifaceIdx,
		Program:   prog,
		Attach:    attachType,
	}

	return link.AttachTCX(tcxOpts)
}

// setupRoutes 配置Gin路由
// 包括API接口和WebSocket端点
func setupRoutes(r *gin.Engine, hub *websocket.Hub) {
	// ========== 事件查询API ==========

	// 获取最近的进程事件
	r.GET("/api/events", func(c *gin.Context) {
		events, err := models.GetRecentEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	// 获取最近的网络事件
	r.GET("/api/network-events", func(c *gin.Context) {
		events, err := models.GetRecentNetworkEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	// ========== 策略管理API ==========

	// 获取监控状态
	r.GET("/api/policy/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"execve_enabled":  isExecveMonitoringEnabled(),
			"network_enabled": isNetworkMonitoringEnabled(),
		})
	})

	// 设置execve监控开关
	r.POST("/api/policy/execve/:enabled", func(c *gin.Context) {
		enabled := c.Param("enabled") == "true"
		setExecveMonitoringEnabled(enabled)
		c.JSON(http.StatusOK, gin.H{"execve_enabled": enabled})
	})

	// 设置网络监控开关
	r.POST("/api/policy/network/:enabled", func(c *gin.Context) {
		enabled := c.Param("enabled") == "true"
		setNetworkMonitoringEnabled(enabled)
		c.JSON(http.StatusOK, gin.H{"network_enabled": enabled})
	})

	// ========== 进程治理API ==========

	type procInfo struct {
		PID        int32   `json:"pid"`
		PPID       int32   `json:"ppid"`
		Name       string  `json:"name"`
		CPUPercent float64 `json:"cpu_percent"`
		MEMPercent float32 `json:"mem_percent"`
		MEMRSS     uint64  `json:"mem_rss"`
		Cmdline    string  `json:"cmdline"`
	}

	var (
		procCache     []procInfo
		procCacheTime time.Time
		procCacheMu   sync.RWMutex

		procCPUTimes   = make(map[int32]float64)
		procCPUTimesMu sync.Mutex
		procCPUTimesAt time.Time
	)

	r.GET("/api/processes", func(c *gin.Context) {
		procCacheMu.RLock()
		if time.Since(procCacheTime) < 2*time.Second && procCache != nil {
			result := procCache
			procCacheMu.RUnlock()
			c.JSON(http.StatusOK, gin.H{"processes": result})
			return
		}
		procCacheMu.RUnlock()

		procs, err := process.Processes()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		now := time.Now()
		numCPU := float64(runtime.NumCPU())

		oldTimes := make(map[int32]float64)
		var oldAt time.Time
		procCPUTimesMu.Lock()
		for pid, t := range procCPUTimes {
			oldTimes[pid] = t
		}
		oldAt = procCPUTimesAt
		procCPUTimes = make(map[int32]float64)
		procCPUTimesAt = now
		procCPUTimesMu.Unlock()

		elapsed := now.Sub(oldAt).Seconds()

		var result []procInfo
		for _, p := range procs {
			name, _ := p.Name()
			if name == "" {
				continue
			}
			ppid, _ := p.Ppid()
			memPercent, _ := p.MemoryPercent()
			memInfo, _ := p.MemoryInfo()
			cmdline, _ := p.Cmdline()

			var memRSS uint64
			if memInfo != nil {
				memRSS = memInfo.RSS
			}

			var cpuPercent float64
			times, err := p.Times()
			if err == nil {
				total := times.User + times.System
				procCPUTimesMu.Lock()
				procCPUTimes[p.Pid] = total
				procCPUTimesMu.Unlock()
				if elapsed > 0 {
					if lastTotal, ok := oldTimes[p.Pid]; ok && lastTotal > 0 {
						delta := total - lastTotal
						rawPercent := (delta / elapsed) * 100
						cpuPercent = rawPercent / numCPU
						if cpuPercent < 0 {
							cpuPercent = 0
						}
						if cpuPercent > 100 {
							cpuPercent = 100
						}
					}
				}
			}

			result = append(result, procInfo{
				PID:        p.Pid,
				PPID:       ppid,
				Name:       name,
				CPUPercent: cpuPercent,
				MEMPercent: memPercent,
				MEMRSS:     memRSS,
				Cmdline:    cmdline,
			})
		}

		procCacheMu.Lock()
		procCache = result
		procCacheTime = time.Now()
		procCacheMu.Unlock()

		c.JSON(http.StatusOK, gin.H{"processes": result})
	})

	// 终止进程
	r.POST("/api/process/kill/:pid", func(c *gin.Context) {
		pidStr := c.Param("pid")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PID"})
			return
		}

		// 发送SIGTERM信号终止进程
		err = syscall.Kill(pid, syscall.SIGTERM)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Process terminated",
			"pid":     pid,
			"signal":  "SIGTERM",
		})
	})

	// 强制终止进程（SIGKILL）
	r.POST("/api/process/kill/:pid/force", func(c *gin.Context) {
		pidStr := c.Param("pid")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PID"})
			return
		}

		err = syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Process killed",
			"pid":     pid,
			"signal":  "SIGKILL",
		})
	})

	// ========== WebSocket端点 ==========

	r.GET("/ws", func(c *gin.Context) {
		hub.ServeWs(c.Writer, c.Request)
	})

	// ========== 静态文件服务 ==========

	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/", "./web/dist/index.html")
	r.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})
}

// ========== 策略管理函数 ==========

// isExecveMonitoringEnabled 检查execve监控是否启用
func isExecveMonitoringEnabled() bool {
	return execveEnabled
}

// setExecveMonitoringEnabled 设置execve监控开关
func setExecveMonitoringEnabled(enabled bool) {
	execveEnabled = enabled
	log.Printf("[Policy] Execve monitoring enabled: %v", enabled)
}

// isNetworkMonitoringEnabled 检查网络监控是否启用
func isNetworkMonitoringEnabled() bool {
	return networkEnabled
}

// setNetworkMonitoringEnabled 设置网络监控开关
func setNetworkMonitoringEnabled(enabled bool) {
	networkEnabled = enabled
	log.Printf("[Policy] Network monitoring enabled: %v", enabled)
}

func getCPUUsage() float64 {
	if cpuObjs == nil || cpuObjs.CpuStats == nil {
		return 0
	}

	cpuUsageMu.Lock()
	defer cpuUsageMu.Unlock()

	var key uint32 = 0
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
		deltaBusy := float64(stat.BusyNs - cpuPrevBusy[i])
		deltaIdle := float64(stat.IdleNs - cpuPrevIdle[i])
		totalBusy += deltaBusy
		totalIdle += deltaIdle
		cpuPrevBusy[i] = stat.BusyNs
		cpuPrevIdle[i] = stat.IdleNs
	}

	total := totalBusy + totalIdle
	if total <= 0 {
		return 0
	}

	return (totalBusy / total) * 100
}

// ========== 主函数 ==========

func main() {
	// 初始化数据库
	_, err := models.InitDB()
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	log.Println("Database initialized")

	// 创建WebSocket Hub
	hub := websocket.NewHub()
	go hub.Run()

	// 创建事件通道（用于插件发送事件）
	eventChan := make(chan *plugin.Event, 256)

	// 启动事件分发器
	go func() {
		for event := range eventChan {
			hub.Broadcast(map[string]interface{}{
				"type": event.Type,
				"data": event.Data,
			})
		}
	}()

	// 移除内存限制（eBPF程序需要锁定内存）
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[warn] failed to remove memlock limit: %v", err)
		log.Println("[warn] eBPF monitoring disabled (requires root)")
	}

	// ========== 加载execve eBPF程序（非root时跳过） ==========
	execveObjs = &execveObjects{}
	if err := loadExecveObjects(execveObjs, nil); err != nil {
		log.Printf("[execve] failed to load execve objects: %v", err)
		log.Println("[execve] execve monitoring disabled (requires root)")
		execveObjs = nil
	} else {
		defer execveObjs.Close()

		// 挂载execve跟踪点
		execveTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.TracepointExecve, nil)
		if err != nil {
			log.Printf("[execve] failed to attach execve tracepoint: %v", err)
			execveObjs.Close()
			execveObjs = nil
		} else {
			defer execveTp.Close()
			execveLinks = append(execveLinks, execveTp)

			// 打开execve事件Ring Buffer
			execveRd, err := ringbuf.NewReader(execveObjs.Events)
			if err != nil {
				log.Printf("[execve] failed to open execve ring buffer: %v", err)
				execveTp.Close()
				execveObjs.Close()
				execveObjs = nil
			} else {
				defer execveRd.Close()

				// 启动goroutine读取execve事件
				go func() {
					for {
						record, err := execveRd.Read()
						if err != nil {
							log.Printf("[execve] failed to read from ring buffer: %v", err)
							return
						}

						var event execveEvent
						if len(record.RawSample) < 152 {
							continue
						}

						// 使用unsafe快速解析二进制数据
						copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)

						// 将字节数组转换为字符串
						comm := string(bytes.Trim(event.Comm[:], "\x00"))
						argv0 := string(bytes.Trim(event.Argv0[:], "\x00"))

						// 检查监控开关
						if !isExecveMonitoringEnabled() {
							continue
						}



						// 保存到数据库
						dbEvent := &models.ExecveEvent{
							PID:   event.PID,
							PPID:  event.PPID,
							Comm:  comm,
							Argv0: argv0,
						}
						if err := models.CreateEvent(dbEvent); err != nil {
							log.Printf("[execve] failed to save event: %v", err)
						}

						// 通过WebSocket实时推送
						hub.Broadcast(map[string]interface{}{
							"type": "execve",
							"data": map[string]interface{}{
								"pid":   event.PID,
								"ppid":  event.PPID,
								"comm":  comm,
								"argv0": argv0,
							},
						})

						log.Printf("[EXECVE] PID=%d PPID=%d Comm=%s Argv0=%s",
							event.PID, event.PPID, comm, argv0)
					}
				}()
			}
		}
	}

	// ========== 加载network eBPF程序 ==========
	networkObjs = &networkObjects{}
	if err := loadNetworkObjects(networkObjs, nil); err != nil {
		log.Printf("[network] failed to load network objects: %v", err)
		log.Println("[network] Network monitoring disabled")
	} else {
		defer networkObjs.Close()

		// 获取所有活动的网络接口
		interfaces := getNetworkInterfaces()
		if len(interfaces) == 0 {
			log.Println("[network] No active network interfaces found")
			log.Println("[network] Network monitoring disabled")
		} else {
			var interfaceNames []string
			for _, iface := range interfaces {
				interfaceNames = append(interfaceNames, iface.Name)
			}
			log.Printf("[network] Found interfaces: %s", strings.Join(interfaceNames, ", "))

			var attachedInterfaces []string

			// 尝试挂载到每个接口
			for _, iface := range interfaces {
				// 挂载ingress程序
				ingressLink, err := attachNetworkProgram(networkObjs, iface.Index, true)
				if err != nil {
					log.Printf("[network] failed to attach ingress to %s: %v", iface.Name, err)
					continue
				}
				defer ingressLink.Close()
				networkLinks = append(networkLinks, ingressLink)

				// 挂载egress程序
				egressLink, err := attachNetworkProgram(networkObjs, iface.Index, false)
				if err != nil {
					log.Printf("[network] failed to attach egress to %s: %v", iface.Name, err)
					ingressLink.Close()
					continue
				}
				defer egressLink.Close()
				networkLinks = append(networkLinks, egressLink)

				attachedInterfaces = append(attachedInterfaces, iface.Name)
				log.Printf("[network] Successfully attached to %s", iface.Name)
			}

			if len(attachedInterfaces) == 0 {
				log.Println("[network] Failed to attach to any interface")
				log.Println("[network] Network monitoring disabled")
			} else {
				log.Printf("[network] Monitoring interfaces: %s", strings.Join(attachedInterfaces, ", "))

				// 打开网络事件Ring Buffer
				networkRd, err := ringbuf.NewReader(networkObjs.NetEvents)
				if err != nil {
					log.Printf("[network] failed to open network ring buffer: %v", err)
				} else {
					defer networkRd.Close()

					// 启动goroutine读取网络事件
					go func() {
						for {
							record, err := networkRd.Read()
							if err != nil {
								log.Printf("[network] failed to read from ring buffer: %v", err)
								return
							}

							var event networkEvent
							if len(record.RawSample) < 28 {
								continue
							}

							// 使用binary解析网络字节序数据
							event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
							event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
							event.DstIP = binary.LittleEndian.Uint32(record.RawSample[8:12])
							event.SrcPort = binary.LittleEndian.Uint16(record.RawSample[12:14])
							event.DstPort = binary.LittleEndian.Uint16(record.RawSample[14:16])
							event.Protocol = record.RawSample[16]
							event.Direction = record.RawSample[17]
							event.PacketSize = binary.LittleEndian.Uint32(record.RawSample[18:22])
							copy(event.Comm[:], record.RawSample[22:38])

							// 检查监控开关
							if !isNetworkMonitoringEnabled() {
								continue
							}

							// 转换数据格式
							comm := string(bytes.Trim(event.Comm[:], "\x00"))
							srcIP := ipToString(event.SrcIP)
							dstIP := ipToString(event.DstIP)
							proto := protocolToString(event.Protocol)
							direction := "ingress"
							if event.Direction == 1 {
								direction = "egress"
							}

							// 保存到数据库
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

							// 通过WebSocket实时推送
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

							log.Printf("[NETWORK] %s %s PID=%d %s:%d -> %s:%d (%s) %d bytes",
								direction, proto, event.PID, srcIP, event.SrcPort, dstIP, event.DstPort, comm, event.PacketSize)
						}
					}()
				}
			}
		}
	}

	cpuObjs = &cpuObjects{}
	if err := loadCpuObjects(cpuObjs, nil); err != nil {
		log.Printf("[cpu] failed to load cpu objects: %v", err)
		log.Println("[cpu] CPU monitoring via eBPF disabled, falling back to gopsutil")
	} else {
		cpuTp, err := link.Tracepoint("sched", "sched_switch", cpuObjs.TracepointSchedSwitch, nil)
		if err != nil {
			log.Printf("[cpu] failed to attach sched_switch tracepoint: %v", err)
			cpuObjs.Close()
			cpuObjs = nil
		} else {
			defer cpuTp.Close()
			cpuLinks = append(cpuLinks, cpuTp)
			log.Println("[cpu] CPU monitoring eBPF program loaded")
			log.Printf("[cpu] Monitoring %d CPUs via eBPF", runtime.NumCPU())
		}
	}

	systemPlugin := plugin.NewSystemMonitorPlugin()

	if cpuObjs != nil {
		plugin.GetCPUUsage = getCPUUsage
		log.Println("[cpu] eBPF CPU monitoring enabled for system plugin")
	}

	if err := systemPlugin.Load(); err != nil {
		log.Printf("[system] Failed to load system plugin: %v", err)
	} else {
		if err := systemPlugin.Attach(); err != nil {
			log.Printf("[system] Failed to attach system plugin: %v", err)
		} else {
			// 在独立goroutine中运行系统监控插件
			go func() {
				if err := systemPlugin.Start(eventChan); err != nil {
					log.Printf("[system] System plugin stopped: %v", err)
				}
			}()
			log.Println("[system] System monitor plugin started")
		}
	}

	log.Println("eBPF Sentinel started! Monitoring execve syscalls, network traffic, and system metrics...")

	// 设置Gin路由
	r := gin.Default()
	setupRoutes(r, hub)

	log.Println("API server started on :8080")
	log.Println("WebSocket endpoint: ws://localhost:8080/ws")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
