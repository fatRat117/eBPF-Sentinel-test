package main

import (
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/process"
)

type procInfo struct {
	PID        int32   `json:"pid"`
	PPID       int32   `json:"ppid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MEMPercent float32 `json:"mem_percent"`
	MEMRSS     uint64  `json:"mem_rss"`
	Cmdline    string  `json:"cmdline"`
}

type processSnapshotter struct {
	cache     []procInfo
	cacheTime time.Time
	cacheMu   sync.RWMutex

	cpuTimes   map[int32]float64
	cpuTimesAt time.Time
	cpuTimesMu sync.Mutex
}

func newProcessSnapshotter() *processSnapshotter {
	return &processSnapshotter{
		cpuTimes: make(map[int32]float64),
	}
}

func registerProcessRoutes(r *gin.Engine) {
	snapshotter := newProcessSnapshotter()

	r.GET("/api/processes", func(c *gin.Context) {
		if !isExecveMonitoringEnabled() {
			c.JSON(http.StatusOK, gin.H{
				"processes":                  []procInfo{},
				"process_management_enabled": false,
			})
			return
		}

		result, err := snapshotter.List()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"processes":                  result,
			"process_management_enabled": true,
		})
	})

	r.POST("/api/process/kill/:pid", requireMutationAccess(), func(c *gin.Context) {
		killProcess(c, syscall.SIGTERM, "SIGTERM", "Process terminated")
	})

	r.POST("/api/process/kill/:pid/force", requireMutationAccess(), func(c *gin.Context) {
		killProcess(c, syscall.SIGKILL, "SIGKILL", "Process killed")
	})
}

// List 获取进程快照 / Returns a cached process snapshot.
func (s *processSnapshotter) List() ([]procInfo, error) {
	s.cacheMu.RLock()
	if time.Since(s.cacheTime) < 2*time.Second && s.cache != nil {
		result := s.cache
		s.cacheMu.RUnlock()
		return result, nil
	}
	s.cacheMu.RUnlock()

	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	numCPU := float64(runtime.NumCPU())
	oldTimes, oldAt := s.swapCPUTimes(now)
	elapsed := 0.0
	if !oldAt.IsZero() {
		elapsed = now.Sub(oldAt).Seconds()
	}

	result := make([]procInfo, 0, len(procs))
	for _, p := range procs {
		info, ok := s.readProcess(p, oldTimes, elapsed, numCPU)
		if ok {
			result = append(result, info)
		}
	}

	s.cacheMu.Lock()
	s.cache = result
	s.cacheTime = time.Now()
	s.cacheMu.Unlock()

	return result, nil
}

func (s *processSnapshotter) swapCPUTimes(now time.Time) (map[int32]float64, time.Time) {
	s.cpuTimesMu.Lock()
	defer s.cpuTimesMu.Unlock()

	oldTimes := s.cpuTimes
	oldAt := s.cpuTimesAt
	s.cpuTimes = make(map[int32]float64, len(oldTimes))
	s.cpuTimesAt = now
	return oldTimes, oldAt
}

func (s *processSnapshotter) readProcess(p *process.Process, oldTimes map[int32]float64, elapsed float64, numCPU float64) (procInfo, bool) {
	name, _ := p.Name()
	if name == "" {
		return procInfo{}, false
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
	if times, err := p.Times(); err == nil {
		total := times.User + times.System
		s.cpuTimesMu.Lock()
		s.cpuTimes[p.Pid] = total
		s.cpuTimesMu.Unlock()

		if elapsed > 0 {
			if lastTotal, ok := oldTimes[p.Pid]; ok && total >= lastTotal {
				rawPercent := ((total - lastTotal) / elapsed) * 100
				cpuPercent = rawPercent / numCPU
				if cpuPercent > 100 {
					cpuPercent = 100
				}
			}
		}
	}

	return procInfo{
		PID:        p.Pid,
		PPID:       ppid,
		Name:       name,
		CPUPercent: cpuPercent,
		MEMPercent: memPercent,
		MEMRSS:     memRSS,
		Cmdline:    cmdline,
	}, true
}

func killProcess(c *gin.Context, signal syscall.Signal, signalName string, message string) {
	if !isExecveMonitoringEnabled() {
		c.JSON(http.StatusForbidden, gin.H{"error": "Process management is disabled by policy"})
		return
	}

	pid, err := strconv.Atoi(c.Param("pid"))
	if err != nil || pid <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PID"})
		return
	}

	if err := syscall.Kill(pid, signal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": message,
		"pid":     pid,
		"signal":  signalName,
	})
}
