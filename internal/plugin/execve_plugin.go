package plugin

import (
	"bytes"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecveEvent 对应eBPF中的事件结构
// 必须与ebpf/execve.c中的struct event完全匹配
type ExecveEvent struct {
	PID   uint32    // 进程ID
	PPID  uint32    // 父进程ID
	Comm  [16]byte  // 进程名（固定长度字节数组）
	Argv0 [128]byte // 命令行参数（固定长度字节数组）
}

// execveObjects 由bpf2go生成的eBPF对象结构
// 包含eBPF程序和Maps的引用
type execveObjects struct {
	TracepointExecve *ebpf.Program `ebpf:"tracepoint_execve"` // execve跟踪点程序
	Events           *ebpf.Map     `ebpf:"events"`            // Ring Buffer事件Map
}

// Close 关闭eBPF对象，释放资源
func (o *execveObjects) Close() error {
	if o.TracepointExecve != nil {
		o.TracepointExecve.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	return nil
}

// ExecvePlugin execve监控插件
// 监控系统中所有execve系统调用，记录进程创建事件
type ExecvePlugin struct {
	BasePlugin
	objs      *execveObjects  // eBPF对象
	reader    *ringbuf.Reader // Ring Buffer读取器
	eventChan chan<- *Event   // 事件输出通道
}

// NewExecvePlugin 创建execve插件实例
func NewExecvePlugin() *ExecvePlugin {
	return &ExecvePlugin{
		BasePlugin: BasePlugin{
			Name_:        "execve",
			Description_: "Monitor execve system calls - track process creation events",
		},
	}
}

// Load 加载eBPF对象到内核
// 1. 移除内存限制
// 2. 加载eBPF程序和Maps
func (p *ExecvePlugin) Load() error {
	// 移除内存限制（eBPF需要锁定内存）
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// 这里需要实际加载eBPF对象
	// 由于bpf2go生成的代码在main包，我们需要重新组织代码结构
	// 暂时使用占位符实现
	log.Printf("[%s] Loading eBPF objects...", p.Name_)
	return nil
}

// Attach 挂载eBPF程序到内核跟踪点
// 将程序挂载到syscalls:sys_enter_execve跟踪点
func (p *ExecvePlugin) Attach() error {
	if p.objs == nil || p.objs.TracepointExecve == nil {
		return nil // 占位符实现
	}

	// 挂载到execve系统调用入口
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", p.objs.TracepointExecve, nil)
	if err != nil {
		return err
	}
	p.Links = append(p.Links, tp)

	// 打开Ring Buffer用于读取事件
	reader, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		return err
	}
	p.reader = reader

	return nil
}

// Close 清理插件资源
// 关闭Ring Buffer和eBPF对象
func (p *ExecvePlugin) Close() error {
	if p.reader != nil {
		p.reader.Close()
	}
	if p.objs != nil {
		p.objs.Close()
	}
	return nil
}

// Start 开始读取execve事件
// 这是一个阻塞调用，应该在独立的goroutine中运行
// 持续从Ring Buffer读取事件并发送到eventChan
func (p *ExecvePlugin) Start(eventChan chan<- *Event) error {
	p.eventChan = eventChan

	if p.reader == nil {
		return nil // 占位符实现
	}

	// 持续读取事件
	for {
		record, err := p.reader.Read()
		if err != nil {
			log.Printf("[%s] failed to read from ring buffer: %v", p.Name_, err)
			return err
		}

		// 解析事件数据
		var e ExecveEvent
		if len(record.RawSample) < 152 {
			continue
		}

		// 使用unsafe快速复制二进制数据
		copy((*[152]byte)(unsafe.Pointer(&e))[:], record.RawSample)

		// 将字节数组转换为字符串
		comm := string(bytes.Trim(e.Comm[:], "\x00"))
		argv0 := string(bytes.Trim(e.Argv0[:], "\x00"))

		// 创建通用事件结构
		event := &Event{
			Type:      "execve",
			Timestamp: time.Now().Unix(),
			Data: map[string]interface{}{
				"pid":   e.PID,
				"ppid":  e.PPID,
				"comm":  comm,
				"argv0": argv0,
			},
		}

		// 发送事件到通道（非阻塞）
		select {
		case eventChan <- event:
		default:
			log.Printf("[%s] event channel full, dropping event", p.Name_)
		}
	}
}
