# eBPF-Sentinel 插件化改造 — GPT-5.5 实施 Prompt

> **目标**: 将 eBPF-Sentinel 从"monitor_runtime.go 直接管理 eBPF 生命周期"改造为"Plugin 接口 + Manager 统一管理"的插件化架构。
> **不涉及**: eBPF C 程序 (ebpf/*.c)、前端 UI、新的监控功能。仅做架构重构，保持行为100%一致。

---

## 一、项目背景

eBPF-Sentinel 是一个 Go + eBPF 的 Linux 安全监控工具。通过 eBPF 程序挂载到内核钩子采集进程创建 (execve)、网络流量 (TC) 和 CPU 使用率 (sched_switch) 事件，经 WebSocket 推送到单文件 SPA 前端展示，同时持久化到 SQLite。

**核心依赖**:
- `github.com/cilium/ebpf v0.16` — Go 原生 eBPF 库
- `github.com/gin-gonic/gin v1.12` — HTTP 框架
- `github.com/gorilla/websocket v1.5` — WebSocket
- `gorm.io/gorm` + SQLite — 持久化
- `github.com/shirou/gopsutil/v3` — Fallback 系统指标

**生成工具**: `bpf2go` 将 `ebpf/*.c` 编译为 `*_bpfel.o` 字节码，嵌入 Go，自动生成 `*_bpfel.go` 类型绑定（在 `main` package 中）。

---

## 二、当前状态诊断

### 2.1 已完成的插件化准备

| 文件 | 状态 | 说明 |
|------|------|------|
| `internal/plugin/plugin.go` | ✅ 完整 | Plugin 接口 (7方法)、BasePlugin、Manager、Event 类型 |
| `internal/plugin/system_plugin.go` | ✅ 完整 | SystemMonitorPlugin 实现，被 main.go 直接使用 |
| `internal/plugin/execve_plugin.go` | ⚠️ 占位符 | 结构完整但 Load() 返回 nil，未接入 bpf2go 对象 |

### 2.2 未完成的部分（本次改造目标）

| 问题 | 现状 | 目标 |
|------|------|------|
| **eBPF 生命周期** | `monitor_runtime.go` 在 main package 直接管理全局变量 `execveObjs`/`networkObjs`/`cpuObjs` | 由 `ExecvePlugin`/`NetworkPlugin`/`CPUPlugin` 各自拥有 |
| **Network 插件** | 不存在 | 新建 `internal/plugin/network_plugin.go` |
| **CPU 插件** | CPU 监控在 `monitor_runtime.go` 全局函数 | 新建 `internal/plugin/cpu_plugin.go` |
| **Event 类型分散** | `ebpf_events.go` (main) 定义二进制兼容结构体；plugin 包有自己的 `ExecveEvent` | 统一使用 plugin 包结构体，ebpf_events.go 只保留常量 |
| **bpf2go 代码位置** | 生成在 main package | 用 `//go:generate` 指令生成到 plugin 子包，或通过类型嵌入桥接 |
| **Policy 管理** | `policy.go` 引用全局 `execveObjs`/`networkObjs` | 每个插件提供 `SetEnabled(bool)` 方法 |
| **main.go 启动** | 手动调用 `startEBPFMonitors()` + `startSystemPlugin()` | 全部走 `Manager.Register → LoadAll → AttachAll → StartAll` |

### 2.3 关键架构约束

1. **bpf2go 生成的 `*_bpfel.go` 文件在 `main` package**。不能直接移到 `plugin` package，因为 `//go:embed` 路径依赖。解决方案：在 plugin 包中定义接口类型，由 main 包的具体类型实现。
2. **`ringbuf.Reader` 的 `Read()` 是阻塞调用**，必须在独立 goroutine 中运行，通过 channel 输出事件。
3. **`link.Link` 需要保存引用**以便 Detach → Close 清理。
4. **policy 中的 `atomic.Bool` 需要同时更新 eBPF Map**（monitoring_enabled 等）。
5. **`ebpf_events.go` 中的 `execveEvent`/`networkEvent` 必须与 C 结构体二进制对齐**，否则 ringbuf 解析出错。

---

## 三、目标架构

```
main.go
  ├── init DB
  ├── init WebSocket Hub + event dispatch goroutine
  ├── init Plugin Manager
  │     ├── manager.Register(NewExecvePlugin())
  │     ├── manager.Register(NewNetworkPlugin())
  │     ├── manager.Register(NewCPUPlugin())
  │     └── manager.Register(NewSystemMonitorPlugin())
  ├── manager.LoadAll() → manager.AttachAll() → manager.StartAll(eventChan)
  └── gin routes + r.Run(":8080")

每个 Plugin 自包含:
  - 拥有自己的 eBPF Objects (*_bpfel.go 中的 *Objects)
  - 拥有自己的 []link.Link
  - 拥有自己的 ringbuf.Reader
  - 通过 Start(eventChan) 输出 plugin.Event
  - 通过 SetEnabled(bool) 控制启停
```

---

## 四、分步实施计划（按依赖顺序）

### Step 0: 准备工作 — 定义共享类型

**文件**: `internal/plugin/types.go`（新建）

定义所有插件共同使用的类型，避免循环依赖：

```go
// EventBinary 是 eBPF ringbuf 事件的 Go 侧二进制表示。
// 必须与 eBPF C 结构体完全对齐。
type ExecveEventBinary struct {
    PID   uint32
    PPID  uint32
    Comm  [16]byte
    Argv0 [128]byte
}

type NetworkEventBinary struct {
    PID        uint32
    SrcIP      uint32
    DstIP      uint32
    SrcPort    uint16
    DstPort    uint16
    Protocol   uint8
    Direction  uint8
    PacketSize uint32
    Comm       [16]byte
}

type CPUStatBinary struct {
    BusyNs uint64
    IdleNs uint64
    LastTs uint64
    IsBusy uint32
    _      [4]byte  // padding
}

const ExecveEventSize  = 152  // 4+4+16+128
const NetworkEventSize = 38   // 4+4+4+2+2+1+1+4+16
```

> **注意**: 这些结构体必须与 `ebpf/cpu.c`、`ebpf/execve.c`、`ebpf/network.c` 中的 C struct 二进制布局完全一致。

---

### Step 1: 重构 ExecvePlugin — 从占位符到完整实现

**文件**: `internal/plugin/execve_plugin.go`（重写）

**需要实现的功能**:

1. **拥有 eBPF Objects**: 利用 bpf2go 生成的 `execveObjects`（在 main package）。解决方案：定义接口 `ExecveObjectAccessor`:

```go
// 在 execve_plugin.go 中定义接口
type ExecveBPFProvider interface {
    Load() (*ebpf.CollectionSpec, error)
    LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error
}
```

在 main package 中实现该接口（包装 `loadExecveObjects`）。

2. **Load()**: 调用 `rlimit.RemoveMemlock()` → 通过 provider 加载 eBPF 对象 → 调用 `syncMonitoringMap(true)` 同步初始状态。

3. **Attach()**: `link.Tracepoint("syscalls", "sys_enter_execve", ...)` → 保存 link → `ringbuf.NewReader(events_map)` → 保存 reader。

4. **Start(chan<- *Event)**: `go func() { for { record := reader.Read(); 解析 → 检查监控开关 → 发送 Event } }()`。

5. **SetEnabled(bool)**: 更新 eBPF `monitoring_enabled` Map → 更新 atomic.Bool。

6. **Detach()/Close()**: 清理 links → 关闭 reader → 关闭 objects。

**关键代码模式** (从 `monitor_runtime.go` 迁移):

```go
// 解析 execve 二进制事件
var raw ExecveEventBinary
copy((*[ExecveEventSize]byte)(unsafe.Pointer(&raw))[:], record.RawSample[:ExecveEventSize])
comm := string(bytes.Trim(raw.Comm[:], "\x00"))
argv0 := string(bytes.Trim(raw.Argv0[:], "\x00"))

// 发送通用事件
eventChan <- &Event{
    Type: "execve",
    Timestamp: time.Now().Unix(),
    Data: map[string]interface{}{
        "pid": raw.PID, "ppid": raw.PPID, "comm": comm, "argv0": argv0,
    },
}
```

---

### Step 2: 新建 NetworkPlugin

**文件**: `internal/plugin/network_plugin.go`（新建）

**与 ExecvePlugin 类似，额外处理**:

1. **多网卡挂载**: 枚举所有活跃非 lo 网卡 → 对每个挂载 tc_ingress + tc_egress。
2. **网络事件解析**: 使用 `binary.LittleEndian` 逐字段解析（因为结构体有 padding）。
3. **白名单管理**: 暴露 `AddIPWhitelist(ip)`, `RemoveIPWhitelist(ip)`, `AddPortWhitelist(port)`, `RemovePortWhitelist(port)` 方法。
4. **IP 地址转换**: `ipToString(uint32)` → 点分十进制。

**关键解析代码**（从 `monitor_runtime.go` 的 `readNetworkEvents` 迁移）:

```go
event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
event.DstIP = binary.LittleEndian.Uint32(record.RawSample[8:12])
event.SrcPort = binary.LittleEndian.Uint16(record.RawSample[12:14])
event.DstPort = binary.LittleEndian.Uint16(record.RawSample[14:16])
event.Protocol = record.RawSample[16]
event.Direction = record.RawSample[17]
event.PacketSize = binary.LittleEndian.Uint32(record.RawSample[18:22])
copy(event.Comm[:], record.RawSample[22:38])
```

---

### Step 3: 新建 CPUPlugin

**文件**: `internal/plugin/cpu_plugin.go`（新建）

**特殊之处**: CPU 插件不产生事件流（不往 eventChan 写），而是提供一个 `GetCPUUsage() float64` 回调。

实现:
1. Load: 加载 cpu eBPF 对象 → 挂载到 `sched:sched_switch` tracepoint。
2. 提供 `GetCPUUsage() float64` 方法（从 `monitor_runtime.go` 的 `getCPUUsage()` 迁移）。
3. 需要缓存上次的 per-CPU busy/idle 值以计算差值。

**与其他插件的交互**: SystemMonitorPlugin 通过 `GetCPUUsage` 函数变量获取 CPU 使用率。CPUPlugin 在 Attach 后将自己的 `GetCPUUsage` 注入到 `SystemMonitorPlugin.GetCPUUsage`。

---

### Step 4: 重构 SystemMonitorPlugin

**文件**: `internal/plugin/system_plugin.go`（修改）

**当前状态**: 已完整实现。需要改动：
1. 移除全局变量 `var GetCPUUsage func() float64`，改为实例字段 `cpuProvider func() float64`。
2. 在 `Start()` 中通过 `cpuProvider` 获取 CPU 使用率。

---

### Step 5: 重构 policy.go — 策略管理归属插件

**文件**: `policy.go`（修改）

**当前**: 全局 `execveEnabled`/`networkEnabled` atomic.Bool + 直接访问 `execveObjs`/`networkObjs`。

**改造后**: 
1. 移除对 `execveObjs`/`networkObjs` 全局变量的直接引用。
2. `isExecveMonitoringEnabled()` 改为调用 `execvePlugin.IsEnabled()`。
3. `setExecveMonitoringEnabled(bool)` 改为调用 `execvePlugin.SetEnabled(bool)`。
4. `syncXxxMap` 函数移到对应插件内部。

**接口设计**: 在 plugin 包中添加 `PolicyControl` 接口：

```go
type PolicyControl interface {
    IsEnabled() bool
    SetEnabled(bool) error
}
```

ExecvePlugin 和 NetworkPlugin 实现此接口。

**注意**: main.go 中的 `dispatchPluginEvents` 已通过 `isExecveMonitoringEnabled()` / `isNetworkMonitoringEnabled()` 做防御检查。这些函数调用需要改为调用插件的 `IsEnabled()`。

---

### Step 6: 重构 main.go — 统一插件化入口

**文件**: `main.go`（修改）

**改造前**:
```go
eventChan := make(chan *plugin.Event, 256)
go dispatchPluginEvents(hub, eventChan)
cpuUsageFn := startEBPFMonitors(eventChan)
startSystemPlugin(eventChan, cpuUsageFn)
```

**改造后**:
```go
eventChan := make(chan *plugin.Event, 256)
go dispatchPluginEvents(hub, eventChan)

manager := plugin.NewManager()

execvePlugin := plugin.NewExecvePlugin(/* bpfProvider */)
networkPlugin := plugin.NewNetworkPlugin(/* bpfProvider */)
cpuPlugin := plugin.NewCPUPlugin(/* bpfProvider */)
sysPlugin := plugin.NewSystemMonitorPlugin(cpuPlugin.GetCPUUsage)

manager.Register(execvePlugin)
manager.Register(networkPlugin)
manager.Register(cpuPlugin)
manager.Register(sysPlugin)

if err := manager.LoadAll(); err != nil { log.Fatalf(...) }
if err := manager.AttachAll(); err != nil { log.Fatalf(...) }
manager.StartAll(eventChan)
```

**policy 函数适配**（在 main.go 或 policy.go 中）:
```go
func isExecveMonitoringEnabled() bool { return execvePlugin.IsEnabled() }
func setExecveMonitoringEnabled(v bool) error { return execvePlugin.SetEnabled(v) }
```

---

### Step 7: 清理 monitor_runtime.go

**文件**: `monitor_runtime.go`

**操作**: **全部删除**，或保留为一段注释说明"已迁移至 plugin 包"。

所有逻辑已迁移至对应 Plugin:
- `startExecveMonitor` / `readExecveEvents` → `ExecvePlugin`
- `startNetworkMonitor` / `readNetworkEvents` → `NetworkPlugin`
- `startCPUMonitor` / `getCPUUsage` → `CPUPlugin`
- `closeLinks` → 各插件 `Detach()`
- 全局变量 `execveObjs`/`networkObjs`/`cpuObjs`/`*Links` → 各插件实例字段

---

### Step 8: 清理 ebpf_events.go

**文件**: `ebpf_events.go`

**操作**: 
1. 如果有 `ExecveEventSize` / `NetworkEventSize` 常量被其他地方引用，保留。
2. `execveEvent` / `networkEvent` 结构体如不再被 main 包直接使用，可删除（已迁移到 `plugin/types.go`）。

---

### Step 9: 处理 bpf2go 代码生成依赖

**问题**: `execve_x86_bpfel.go` / `network_x86_bpfel.go` / `cpu_bpfel.go` 都在 `main` package，plugin 包无法直接 import main 包。

**方案**: 在 plugin 包中定义接口，main 包提供具体实现：

```go
// plugin/bpf_providers.go（新建）
type BPFCollectionProvider interface {
    LoadSpec() (*ebpf.CollectionSpec, error)
    LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error
}
```

每个 Plugin 构造时接收一个 `BPFCollectionProvider`，main 包创建如下适配器：

```go
// 在 main 包中
type execveBPFProvider struct{}
func (execveBPFProvider) LoadSpec() (*ebpf.CollectionSpec, error) { return loadExecve() }
func (execveBPFProvider) LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error {
    return loadExecveObjects(obj, opts)
}
```

**或更简单**: 在 plugin 包中直接使用 `*ebpf.CollectionSpec` 和 `*ebpf.CollectionOptions`，由 main 包在注册插件时传入。这避免了接口抽象的开销。

**推荐方案**: 让每个 Plugin 的构造函数接受 `*ebpf.CollectionSpec`（通过调用 main 包的 `loadXxx()` 函数获取），Plugin 自己的 `Load()` 方法调用 `spec.LoadAndAssign(obj, opts)`。

---

### Step 10: 更新路由中的 policy 引用

**文件**: `routes.go`

`routes.go` 中引用了 `isExecveMonitoringEnabled()` / `isNetworkMonitoringEnabled()` / `setExecveMonitoringEnabled()` / `setNetworkMonitoringEnabled()`。这些函数仍在 `policy.go` 中定义，但内部实现改为调用插件方法。

**不需要改 routes.go 本身**，只要 policy 函数签名不变。

---

## 五、实施约束

### 5.1 必须保持的行为

1. **事件格式不变**: WebSocket 广播的 JSON `{"type":"execve","timestamp":...,"data":{...}}` 必须与改造前完全一致。
2. **API 接口不变**: `/api/policy/execve/:enabled` 等端点行为不变。
3. **数据库 schema 不变**: SQLite 表结构不修改。
4. **启动顺序不变**: DB → WebSocket Hub → eBPF Load → eBPF Attach → Start → HTTP Listen。
5. **错误处理**: 插件加载失败时不应导致整个程序退出，应优雅降级（log + 跳过该插件）。

### 5.2 代码规范

1. 所有新增 Go 文件使用 `package plugin`。
2. 函数名使用驼峰命名，中文注释可保留但新代码优先英文。
3. 不要在 plugin 包中 import main 包。
4. 不要修改 `*_bpfel.go` 生成文件。
5. 不要修改 `ebpf/*.c` 文件。
6. Ringbuf 解析使用 `unsafe.Pointer` 零拷贝模式（ExecveEvent），或 `binary.LittleEndian` 逐字段解析（NetworkEvent）。

### 5.3 并发安全

1. `ringbuf.Reader.Read()` 是线程安全的，但不要在多个 goroutine 中共享同一个 Reader。
2. `atomic.Bool` 用于启停标志，`sync.Mutex` 用于 CPU 统计。
3. `Manager` 的 `plugins` map 已用 `sync.RWMutex` 保护。
4. Plugin 的 `SetEnabled()` 可能被 HTTP handler 并发调用，必须线程安全。

---

## 六、文件变更清单（汇总）

| 操作 | 文件 | 说明 |
|------|------|------|
| **新建** | `internal/plugin/types.go` | ExecveEventBinary, NetworkEventBinary, CPUStatBinary + 常量 |
| **新建** | `internal/plugin/bpf_providers.go` | BPFCollectionProvider 接口（可选，取决于方案） |
| **新建** | `internal/plugin/network_plugin.go` | NetworkPlugin 完整实现 (~200行) |
| **新建** | `internal/plugin/cpu_plugin.go` | CPUPlugin 完整实现 (~100行) |
| **重写** | `internal/plugin/execve_plugin.go` | 从占位符改为完整实现 (~150行) |
| **修改** | `internal/plugin/system_plugin.go` | cpuProvider 改为实例字段 |
| **修改** | `internal/plugin/plugin.go` | 如有需要，添加 PolicyControl 接口 |
| **修改** | `policy.go` | 移除全局变量引用，改为调用插件方法 |
| **修改** | `main.go` | 替换 startEBPFMonitors + startSystemPlugin 为 Manager 模式 |
| **修改/删除** | `monitor_runtime.go` | 删除或改为注释 |
| **修改/删除** | `ebpf_events.go` | 保留常量，删除不再使用的结构体 |
| **不变** | `routes.go` | policy 函数签名不变，无需修改 |
| **不变** | `*_bpfel.go` | bpf2go 生成文件，不修改 |
| **不变** | `ebpf/*.c` | eBPF C 程序，不修改 |
| **不变** | `internal/websocket/` | WebSocket，不修改 |
| **不变** | `internal/models/` | 数据模型，不修改 |

---

## 七、验收标准

### 7.1 编译验证

```bash
go build -o eBPF-Sentinel .  # 必须成功，无编译错误
go vet ./...                   # 无 warning
```

### 7.2 运行时验证

```bash
sudo ./eBPF-Sentinel
# 期望输出:
# Database initialized
# [execve] Execve monitoring enabled
# [network] Network monitoring enabled on: eth0
# [cpu] CPU monitoring via eBPF enabled (N CPUs)
# [system] System monitor started
# eBPF Sentinel started! Monitoring...
# API server started on :8080
```

### 7.3 功能验证

```bash
# 1. 事件正常采集
curl http://localhost:8080/api/events        # 应有 execve 事件
curl http://localhost:8080/api/network-events # 应有 network 事件

# 2. 策略开关正常
curl -X POST http://localhost:8080/api/policy/execve/false
# 应返回 {"execve_enabled":false}
# execve 事件应停止

curl -X POST http://localhost:8080/api/policy/execve/true
# execve 事件应恢复

# 3. WebSocket 正常工作
websocat ws://localhost:8080/ws
# 应收到实时 JSON 事件流

# 4. 前端正常
curl http://localhost:8080/  # 应返回监控面板 HTML
```

### 7.4 错误处理验证

```bash
# 以非 root 用户运行（eBPF 加载会失败）
./eBPF-Sentinel
# 期望: 不崩溃，log warn 信息，HTTP 服务仍然启动
# WebSocket + 前端可用，但无 eBPF 事件
```

---

## 八、参考文件索引

| 文件 | 用途 |
|------|------|
| `internal/plugin/plugin.go` | 参考 Plugin 接口和 Manager 模式 |
| `internal/plugin/system_plugin.go` | 参考完整插件实现范例 |
| `internal/plugin/execve_plugin.go` | 待改造的 execve 占位符 |
| `monitor_runtime.go` | 源逻辑：execve/network/cpu 的 Load/Attach/Read |
| `main.go` | 当前启动流程，需改为 Manager 模式 |
| `policy.go` | 当前策略管理，需改为调用插件方法 |
| `ebpf_events.go` | 二进制事件结构体，需迁移到 plugin/types.go |
| `network_utils.go` | IP转换、协议转换、网卡枚举工具函数 |
| `execve_x86_bpfel.go` | bpf2go 生成的 execve 绑定（main package） |
| `network_x86_bpfel.go` | bpf2go 生成的 network 绑定（main package） |
| `cpu_bpfel.go` | bpf2go 生成的 cpu 绑定（main package） |
| `doc/02-architecture-layers/README.md` | 架构层级说明 |
| `recommend.md` | 插件化改造建议 |

---

## 九、注意事项

1. **不要一次改太多导致编译不通过** — 按 Step 0→9 顺序，每步完成后编译验证。
2. **先迁移 ExecvePlugin 作为 MVP** — 验证模式可行后再做 NetworkPlugin 和 CPUPlugin。
3. **保留 `dispatchPluginEvents` 中的防御检查** — 这是之前修复的 toggle bug 的安全网。
4. **bpf2go 生成文件的 import 路径不要手动改** — 它们自动生成在 main package，通过接口桥接而非移动文件。
5. **CPU 插件不输出事件** — 它只提供 `GetCPUUsage()`，由 SystemMonitorPlugin 调用后打包为 system 事件。
