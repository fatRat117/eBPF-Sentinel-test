package plugin

import (
	"github.com/cilium/ebpf/link"
)

// Event 通用事件结构
// 所有插件采集的事件都统一使用此格式，便于统一处理和序列化
type Event struct {
	Type      string                 `json:"type"`      // 事件类型（如：execve, network, file）
	Timestamp int64                  `json:"timestamp"` // 事件发生时间戳（Unix时间）
	Data      map[string]interface{} `json:"data"`      // 事件具体数据（各插件自定义）
}

// Plugin 接口定义
// 所有eBPF监控插件必须实现此接口，以便插件管理器统一管理
type Plugin interface {
	// Name 返回插件名称
	// 用于在管理器中唯一标识插件
	Name() string

	// Description 返回插件描述
	// 用于展示插件的功能说明
	Description() string

	// Load 加载eBPF对象
	// 将编译好的eBPF字节码加载进内核，初始化Maps
	Load() error

	// Attach 挂载eBPF程序到内核
	// 将eBPF程序挂载到指定的跟踪点、kprobe或tc钩子
	Attach() error

	// Detach 卸载eBPF程序
	// 从内核卸载eBPF程序，停止事件采集
	Detach() error

	// Close 清理资源
	// 关闭eBPF对象，释放内存和文件描述符
	Close() error

	// Start 开始读取事件（阻塞调用，应在goroutine中运行）
	// 持续从Ring Buffer读取事件并通过channel发送
	Start(eventChan chan<- *Event) error
}

// BasePlugin 基础插件结构
// 提供插件共用的字段和方法，具体插件可以嵌入此结构
type BasePlugin struct {
	Name_        string      // 插件名称
	Description_ string      // 插件描述
	Objs         interface{} // eBPF对象（由bpf2go生成）
	Links        []link.Link // 挂载点链接（用于卸载）
}

// Name 返回插件名称
func (bp *BasePlugin) Name() string {
	return bp.Name_
}

// Description 返回插件描述
func (bp *BasePlugin) Description() string {
	return bp.Description_
}

// Detach 卸载所有挂载的eBPF程序
func (bp *BasePlugin) Detach() error {
	for _, l := range bp.Links {
		if l != nil {
			l.Close()
		}
	}
	bp.Links = nil
	return nil
}

// Manager 插件管理器
// 统一管理所有插件的生命周期，包括加载、挂载、启动和停止
type Manager struct {
	plugins map[string]Plugin // 插件映射表，key为插件名称
}

// NewManager 创建插件管理器
func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]Plugin),
	}
}

// Register 注册插件到管理器
// 注册后可以通过管理器统一控制插件
func (m *Manager) Register(p Plugin) {
	m.plugins[p.Name()] = p
}

// Get 获取指定名称的插件
// 返回插件实例和是否存在标志
func (m *Manager) Get(name string) (Plugin, bool) {
	p, ok := m.plugins[name]
	return p, ok
}

// List 列出所有已注册的插件
func (m *Manager) List() []Plugin {
	list := make([]Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		list = append(list, p)
	}
	return list
}

// LoadAll 加载所有插件的eBPF对象
// 依次调用每个插件的Load方法
func (m *Manager) LoadAll() error {
	for _, p := range m.plugins {
		if err := p.Load(); err != nil {
			return err
		}
	}
	return nil
}

// AttachAll 挂载所有插件的eBPF程序
// 依次调用每个插件的Attach方法
func (m *Manager) AttachAll() error {
	for _, p := range m.plugins {
		if err := p.Attach(); err != nil {
			return err
		}
	}
	return nil
}

// DetachAll 卸载所有插件的eBPF程序
// 依次调用每个插件的Detach方法
func (m *Manager) DetachAll() error {
	for _, p := range m.plugins {
		if err := p.Detach(); err != nil {
			return err
		}
	}
	return nil
}

// CloseAll 关闭所有插件并释放资源
// 依次调用每个插件的Close方法
func (m *Manager) CloseAll() error {
	for _, p := range m.plugins {
		if err := p.Close(); err != nil {
			return err
		}
	}
	return nil
}
