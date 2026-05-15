package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type execveObjects struct {
	TracepointExecve  *ebpf.Program `ebpf:"tracepoint_execve"`
	Events            *ebpf.Map     `ebpf:"events"`
	MonitoringEnabled *ebpf.Map     `ebpf:"monitoring_enabled"`
}

func (o *execveObjects) Close() error {
	var err error
	if o.TracepointExecve != nil {
		err = errors.Join(err, o.TracepointExecve.Close())
	}
	if o.Events != nil {
		err = errors.Join(err, o.Events.Close())
	}
	if o.MonitoringEnabled != nil {
		err = errors.Join(err, o.MonitoringEnabled.Close())
	}
	return err
}

type ExecvePlugin struct {
	BasePlugin
	provider BPFCollectionProvider
	objs     *execveObjects
	reader   *ringbuf.Reader
	enabled  atomic.Bool
}

func NewExecvePlugin(provider BPFCollectionProvider) *ExecvePlugin {
	p := &ExecvePlugin{
		BasePlugin: BasePlugin{
			Name_:        "execve",
			Description_: "Monitor execve system calls - track process creation events",
		},
		provider: provider,
	}
	p.enabled.Store(true)
	return p
}

func (p *ExecvePlugin) Load() error {
	if p.provider == nil {
		return errors.New("execve BPF provider is nil")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := &execveObjects{}
	if err := p.provider.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load execve objects: %w", err)
	}
	p.objs = objs
	if err := p.syncMonitoringMap(p.IsEnabled()); err != nil {
		return err
	}
	log.Printf("[%s] Execve monitoring enabled", p.Name())
	return nil
}

func (p *ExecvePlugin) Attach() error {
	if p.objs == nil {
		return nil
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", p.objs.TracepointExecve, nil)
	if err != nil {
		return fmt.Errorf("attach execve tracepoint: %w", err)
	}
	p.Links = append(p.Links, tp)

	reader, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		return fmt.Errorf("open execve ring buffer: %w", err)
	}
	p.reader = reader
	return nil
}

func (p *ExecvePlugin) Start(eventChan chan<- *Event) error {
	if p.reader == nil {
		return nil
	}
	for {
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read execve ring buffer: %w", err)
		}
		if len(record.RawSample) < ExecveEventSize {
			continue
		}

		var raw ExecveEventBinary
		copy((*[ExecveEventSize]byte)(unsafe.Pointer(&raw))[:], record.RawSample[:ExecveEventSize])
		if !p.IsEnabled() {
			continue
		}

		comm := string(bytes.Trim(raw.Comm[:], "\x00"))
		argv0 := string(bytes.Trim(raw.Argv0[:], "\x00"))
		select {
		case eventChan <- &Event{
			Type:      "execve",
			Timestamp: time.Now().Unix(),
			Data: map[string]interface{}{
				"pid":   raw.PID,
				"ppid":  raw.PPID,
				"comm":  comm,
				"argv0": argv0,
			},
		}:
		default:
			log.Printf("[%s] event channel full, dropping event", p.Name())
		}
	}
}

func (p *ExecvePlugin) Detach() error {
	return p.BasePlugin.Detach()
}

func (p *ExecvePlugin) Close() error {
	var err error
	if p.reader != nil {
		err = errors.Join(err, p.reader.Close())
		p.reader = nil
	}
	err = errors.Join(err, p.Detach())
	if p.objs != nil {
		err = errors.Join(err, p.objs.Close())
		p.objs = nil
	}
	return err
}

func (p *ExecvePlugin) IsEnabled() bool {
	return p.enabled.Load()
}

func (p *ExecvePlugin) SetEnabled(enabled bool) error {
	if err := p.syncMonitoringMap(enabled); err != nil {
		return err
	}
	p.enabled.Store(enabled)
	log.Printf("[%s] Execve monitoring enabled: %v", p.Name(), enabled)
	return nil
}

func (p *ExecvePlugin) syncMonitoringMap(enabled bool) error {
	if p.objs == nil || p.objs.MonitoringEnabled == nil {
		return nil
	}
	var key uint32
	var value uint32
	if enabled {
		value = 1
	}
	if err := p.objs.MonitoringEnabled.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync execve monitoring map: %w", err)
	}
	return nil
}
