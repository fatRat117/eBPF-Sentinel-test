package plugin

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/net"
)

// GetCPUUsage 用于从eBPF获取CPU使用率的函数
// 由main.go在加载eBPF程序后注入
// 如果为nil，则回退到gopsutil方式
var GetCPUUsage func() float64

// SystemStats 系统统计信息
type SystemStats struct {
	CPUUsage    float64 `json:"cpu_usage"`     // CPU使用率（百分比）
	NetSpeedIn  float64 `json:"net_speed_in"`  // 入站网速（KB/s）
	NetSpeedOut float64 `json:"net_speed_out"` // 出站网速（KB/s）
}

// SystemMonitorPlugin 系统监控插件
// 负责采集CPU使用率和网络速度等系统级指标
type SystemMonitorPlugin struct {
	BasePlugin
	eventChan chan<- *Event
	ctx       context.Context
	cancel    context.CancelFunc

	// 网络统计上一次的数据
	lastNetStats map[string]net.IOCountersStat
	lastNetTime  time.Time
}

// NewSystemMonitorPlugin 创建系统监控插件
func NewSystemMonitorPlugin() *SystemMonitorPlugin {
	return &SystemMonitorPlugin{
		BasePlugin: BasePlugin{
			Name_:        "system",
			Description_: "Monitor system metrics like CPU usage and network speed",
		},
		lastNetStats: make(map[string]net.IOCountersStat),
	}
}

// Load 初始化插件（系统监控插件不需要加载eBPF对象）
func (p *SystemMonitorPlugin) Load() error {
	log.Printf("[%s] System monitor plugin loaded", p.Name_)
	return nil
}

// Attach 启动监控（系统监控插件不需要挂载eBPF程序）
func (p *SystemMonitorPlugin) Attach() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	log.Printf("[%s] System monitor attached", p.Name_)
	return nil
}

// Detach 停止监控
func (p *SystemMonitorPlugin) Detach() error {
	if p.cancel != nil {
		p.cancel()
	}
	log.Printf("[%s] System monitor detached", p.Name_)
	return nil
}

// Close 清理资源
func (p *SystemMonitorPlugin) Close() error {
	return p.Detach()
}

// Start 开始采集系统指标
// 每秒采集一次CPU使用率和网络速度
func (p *SystemMonitorPlugin) Start(eventChan chan<- *Event) error {
	p.eventChan = eventChan

	// 初始化网络统计
	p.initNetStats()

	// 启动采集循环
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return nil
		case <-ticker.C:
			p.collectStats()
		}
	}
}

// initNetStats 初始化网络统计
func (p *SystemMonitorPlugin) initNetStats() {
	stats, err := net.IOCounters(true)
	if err != nil {
		log.Printf("[%s] Failed to init net stats: %v", p.Name_, err)
		return
	}

	for _, stat := range stats {
		p.lastNetStats[stat.Name] = stat
	}
	p.lastNetTime = time.Now()
}

// collectStats 采集系统统计信息
func (p *SystemMonitorPlugin) collectStats() {
	var cpuUsage float64
	if GetCPUUsage != nil {
		cpuUsage = GetCPUUsage()
	}

	// 采集网络速度
	speedIn, speedOut := p.calculateNetSpeed()

	// 创建事件
	event := &Event{
		Type:      "system",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"cpu_usage":     fmt.Sprintf("%.1f", cpuUsage),
			"net_speed_in":  fmt.Sprintf("%.1f", speedIn),
			"net_speed_out": fmt.Sprintf("%.1f", speedOut),
		},
	}

	// 发送事件
	select {
	case p.eventChan <- event:
	default:
		log.Printf("[%s] Event channel full, dropping system stats", p.Name_)
	}
}

// calculateNetSpeed 计算网络速度（KB/s）
func (p *SystemMonitorPlugin) calculateNetSpeed() (float64, float64) {
	// 获取当前网络统计
	stats, err := net.IOCounters(true)
	if err != nil {
		log.Printf("[%s] Failed to get net stats: %v", p.Name_, err)
		return 0, 0
	}

	now := time.Now()
	elapsed := now.Sub(p.lastNetTime).Seconds()

	if elapsed <= 0 || len(p.lastNetStats) == 0 {
		// 第一次采集，只记录数据
		for _, stat := range stats {
			p.lastNetStats[stat.Name] = stat
		}
		p.lastNetTime = now
		return 0, 0
	}

	var totalBytesIn, totalBytesOut uint64
	var lastBytesIn, lastBytesOut uint64

	// 累加所有网卡的流量
	for _, stat := range stats {
		totalBytesIn += stat.BytesRecv
		totalBytesOut += stat.BytesSent

		if lastStat, ok := p.lastNetStats[stat.Name]; ok {
			lastBytesIn += lastStat.BytesRecv
			lastBytesOut += lastStat.BytesSent
		}
	}

	// 计算速度（KB/s）
	speedIn := float64(totalBytesIn-lastBytesIn) / elapsed / 1024
	speedOut := float64(totalBytesOut-lastBytesOut) / elapsed / 1024

	// 更新上一次的数据
	for _, stat := range stats {
		p.lastNetStats[stat.Name] = stat
	}
	p.lastNetTime = now

	return speedIn, speedOut
}
