package plugin

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type cpuObjects struct {
	TracepointSchedSwitch *ebpf.Program `ebpf:"tracepoint_sched_switch"`
	CpuStats              *ebpf.Map     `ebpf:"cpu_stats"`
}

func (o *cpuObjects) Close() error {
	var err error
	if o.TracepointSchedSwitch != nil {
		err = errors.Join(err, o.TracepointSchedSwitch.Close())
	}
	if o.CpuStats != nil {
		err = errors.Join(err, o.CpuStats.Close())
	}
	return err
}

type CPUPlugin struct {
	BasePlugin
	provider BPFCollectionProvider
	objs     *cpuObjects

	mu       sync.Mutex
	prevBusy []uint64
	prevIdle []uint64
}

func NewCPUPlugin(provider BPFCollectionProvider) *CPUPlugin {
	return &CPUPlugin{
		BasePlugin: BasePlugin{
			Name_:        "cpu",
			Description_: "Monitor CPU usage via eBPF sched_switch events",
		},
		provider: provider,
	}
}

func (p *CPUPlugin) Load() error {
	if p.provider == nil {
		return errors.New("cpu BPF provider is nil")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := &cpuObjects{}
	if err := p.provider.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load cpu objects: %w", err)
	}
	p.objs = objs
	return nil
}

func (p *CPUPlugin) Attach() error {
	if p.objs == nil {
		return nil
	}
	tp, err := link.Tracepoint("sched", "sched_switch", p.objs.TracepointSchedSwitch, nil)
	if err != nil {
		return fmt.Errorf("attach sched_switch tracepoint: %w", err)
	}
	p.Links = append(p.Links, tp)
	log.Printf("[%s] CPU monitoring via eBPF enabled (%d CPUs)", p.Name(), runtime.NumCPU())
	return nil
}

func (p *CPUPlugin) Start(eventChan chan<- *Event) error {
	return nil
}

func (p *CPUPlugin) Detach() error {
	return p.BasePlugin.Detach()
}

func (p *CPUPlugin) Close() error {
	var err error
	err = errors.Join(err, p.Detach())
	if p.objs != nil {
		err = errors.Join(err, p.objs.Close())
		p.objs = nil
	}
	return err
}

func (p *CPUPlugin) GetCPUUsage() float64 {
	if p == nil || p.objs == nil || p.objs.CpuStats == nil {
		return 0
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var key uint32
	var stats []CPUStatBinary
	if err := p.objs.CpuStats.Lookup(key, &stats); err != nil {
		log.Printf("[%s] failed to lookup cpu stats: %v", p.Name(), err)
		return 0
	}
	if len(stats) == 0 {
		return 0
	}
	if len(p.prevBusy) != len(stats) {
		p.prevBusy = make([]uint64, len(stats))
		p.prevIdle = make([]uint64, len(stats))
	}

	var totalBusy, totalIdle float64
	for i, stat := range stats {
		if stat.BusyNs < p.prevBusy[i] || stat.IdleNs < p.prevIdle[i] {
			p.prevBusy[i] = stat.BusyNs
			p.prevIdle[i] = stat.IdleNs
			continue
		}

		totalBusy += float64(stat.BusyNs - p.prevBusy[i])
		totalIdle += float64(stat.IdleNs - p.prevIdle[i])
		p.prevBusy[i] = stat.BusyNs
		p.prevIdle[i] = stat.IdleNs
	}

	total := totalBusy + totalIdle
	if total <= 0 {
		return 0
	}
	return (totalBusy / total) * 100
}
