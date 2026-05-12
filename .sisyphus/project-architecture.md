# eBPF-Sentinel 项目架构全解

> **生成时间**: 2026-05-12
> **语言**: Go 1.25 + eBPF C
> **核心栈**: cilium/ebpf + Gin + Gorilla WebSocket + GORM/SQLite

---

## 一、项目概述

eBPF-Sentinel 是一个基于 eBPF 的 Linux 系统安全监控工具，通过将 eBPF 程序挂载到内核钩子点，**零侵入性地**采集系统事件（进程创建、网络流量、CPU 使用率），并通过 WebSocket 实时推送到 Web 前端展示。

**核心能力**:

- 监控所有 `execve()` 系统调用（进程创建事件）
- 监控所有网络流量（TCP/UDP/ICMP），通过 TC 钩子挂载到网卡
- 通过 sched_switch tracepoint 采集 CPU 使用率
- 实时 WebSocket 推送 + SQLite 持久化存储
- REST API 提供策略开关、进程管理、事件查询
- 单文件 SPA 前端，无构建依赖

---

## 二、技术栈

| 层级 | 技术 | 用途 |
|------|------|------|
| eBPF 程序 | C (CO-RE) | 内核态数据采集 |
| BPF 加载库 | `cilium/ebpf v0.16` | Go 原生 eBPF 加载/挂载 |
| 代码生成 | `bpf2go` | C → 编译 → 嵌入 Go |
| HTTP 框架 | `gin-gonic/gin v1.12` | REST API + 静态文件 |
| WebSocket | `gorilla/websocket v1.5` | 实时事件推送 |
| 数据库 | `gorm.io/gorm` + SQLite | 事件持久化 |
| 系统信息 | `shirou/gopsutil/v3` | Fallback CPU/进程信息 |
| 前端 | 原生 HTML/CSS/JS (单文件) | 监控面板 |

---

## 三、目录结构总览

```text
eBPF-Sentinel/
├── main.go                      # ★ 程序入口
├── ebpf_events.go               #   事件结构体定义（与C端对齐）
├── monitor_runtime.go           # ★ eBPF加载/挂载/事件读取核心
├── network_utils.go             #   网络工具函数（IP转换、接口枚举）
├── policy.go                    #   监控策略开关（atomic + eBPF map同步）
├── routes.go                    #   HTTP API 路由注册
├── process_routes.go            #   进程列表/查杀 API
├── security.go                  #   API 鉴权中间件
│
├── ebpf/                        # eBPF C 源码
│   ├── vmlinux.h                #   内核类型定义（CO-RE）
│   ├── cpu.c                    #   CPU 监控 eBPF
│   ├── execve.c                 #   进程创建监控 eBPF
│   └── network.c                #   网络流量监控 eBPF
│
├── *_bpfel.go                   # bpf2go 自动生成（勿手动编辑）
│   ├── cpu_bpfel.go             #   cpu.c → Go 绑定
│   ├── execve_x86_bpfel.go      #   execve.c → Go 绑定
│   └── network_x86_bpfel.go     #   network.c → Go 绑定
│
├── *_bpfel.o                    # 编译后的 BPF 字节码
│   ├── cpu_bpfel.o
│   ├── execve_x86_bpfel.o
│   └── network_x86_bpfel.o
│
├── internal/                    # 内部包
│   ├── plugin/
│   │   ├── plugin.go            #   Plugin 接口 + 管理器
│   │   ├── execve_plugin.go     #   Execve 插件（独立实现）
│   │   └── system_plugin.go     #   系统监控插件（CPU/网络速度）
│   ├── websocket/
│   │   └── hub.go               #   WebSocket Hub（客户端管理+广播）
│   └── models/
│       └── event.go             #   数据模型 + SQLite 初始化
│
├── web/dist/                    # ★ 单文件前端
│   └── index.html               #   监控面板 SPA
│
├── scripts/
│   └── stress_test.sh           #   压力测试脚本
│
├── doc/                         # 项目文档
├── go.mod / go.sum              # Go 依赖管理
├── sentinel.db                  # SQLite 数据库文件（运行时生成）
└── eBPF-Sentinel                # 编译产物
```

---

## 四、文件逐一详解

### 4.1 入口文件

#### `main.go` — 程序启动入口

**启动流程（按顺序）**:

```text
1. models.InitDB()              → 初始化 SQLite，自动建表
2. websocket.NewHub()           → 创建 WebSocket Hub
3. go hub.Run()                 → 启动 Hub 主循环（goroutine）
4. make(chan *plugin.Event,256) → 创建事件通道（容量256）
5. go dispatchPluginEvents()    → 启动事件分发 goroutine
6. startEBPFMonitors(eventChan) → 加载 eBPF 程序（返回 cpuUsageFn）
7. startSystemPlugin(...)       → 启动系统监控插件
8. gin.Default() + setupRoutes  → 注册 HTTP/WS 路由
9. r.Run(":8080")               → 阻塞监听 8080 端口
```

**关键函数**:

- `dispatchPluginEvents(hub, eventChan)` — 从 channel 读取事件 → 持久化到 SQLite → WebSocket 广播
- `persistEvent(event)` — 根据 `event.Type` 将事件写入对应数据库表
- `startSystemPlugin(eventChan, cpuUsageFn)` — 将 eBPF CPU 监控函数注入系统插件

---

### 4.2 eBPF C 程序

#### `ebpf/cpu.c` — CPU 使用率监控

| 项目 | 说明 |
|------|------|
| 挂载点 | `SEC("tp/sched/sched_switch")` — 调度切换跟踪点 |
| Map | `cpu_stats` — `BPF_MAP_TYPE_PERCPU_ARRAY`，每核独立结构 |
| 数据结构 | `struct cpu_stat { busy_ns, idle_ns, last_ts, is_busy }` |
| 原理 | 每次进程切换时计算上一任务的 CPU 时间，按 busy/idle 分类累加 |
| 读取方式 | 用户态定期从 PERCPU_ARRAY 读出各核 busy/idle 差值计算百分比 |

#### `ebpf/execve.c` — 进程创建监控

| 项目 | 说明 |
|------|------|
| 挂载点 | `SEC("tp/syscalls/sys_enter_execve")` — execve 系统调用入口 |
| 输出 Map | `events` — `BPF_MAP_TYPE_RINGBUF` (256KB)，事件环形缓冲区 |
| 控制 Map | `monitoring_enabled` — `BPF_MAP_TYPE_ARRAY`，运行时开关 |
| 采集字段 | pid, ppid, comm(进程名), argv0(命令行) |
| 读取方式 | 用户态通过 `ringbuf.NewReader()` 持续读取事件 |

#### `ebpf/network.c` — 网络流量监控

| 项目 | 说明 |
|------|------|
| 挂载点 | `SEC("tc")` — `tc_ingress` + `tc_egress` 分别处理入/出站 |
| 输出 Map | `net_events` — `BPF_MAP_TYPE_RINGBUF` (256KB) |
| 过滤 Map | `ip_whitelist` + `port_whitelist` + 对应 enable 开关 |
| 采样 | `sample_counter` — 每 100 个包采样 1 个（`SAMPLE_RATE=100`） |
| 采集字段 | pid, src_ip, dst_ip, src_port, dst_port, protocol, direction, packet_size, comm |
| 挂载方式 | Go 侧通过 `link.AttachTCX()` 挂载到所有活跃非lo网卡 |

---

### 4.3 自动生成文件

#### `*_bpfel.go` — bpf2go 生成的 Go 绑定

**生成命令**: `go generate` 触发 `bpf2go` 工具：

```text
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go cpu ebpf/cpu.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go execve ebpf/execve.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go network ebpf/network.c
```

每个 `*_bpfel.go` 文件包含：

1. **嵌入的字节码**: `//go:embed *_bpfel.o` — 将编译好的 BPF 字节码嵌入 Go binary
2. **类型定义**: `*Objects`, `*Programs`, `*Maps` 结构体（例如 `execveObjects` 包含 `TracepointExecve *ebpf.Program` 和 `Events *ebpf.Map`）
3. **加载函数**: `loadXxxObjects()` — 将字节码加载到内核并填充 Objects 结构
4. **Close 函数**: 清理资源

**对应的 `.o` 文件**（如 `execve_x86_bpfel.o`）是 clang/LLVM 编译后的 BPF ELF 目标文件。

---

### 4.4 运行时核心

#### `monitor_runtime.go` — eBPF 加载/挂载/事件读取

**这是整个 eBPF 生命周期管理的核心文件**，负责三个监控器的完整生命周期。

**核心函数**:

| 函数 | 职责 |
|------|------|
| `startEBPFMonitors(eventChan)` | 入口：移除内存锁 → 依次启动三个监控器 |
| `startExecveMonitor(eventChan)` | 加载 execve BPF 对象 → 挂载到 `sys_enter_execve` tracepoint → 打开 ringbuf → `go readExecveEvents()` |
| `readExecveEvents(rd, eventChan)` | 阻塞循环：从 ringbuf 读 → 二进制解析 → 组装 `plugin.Event` → 发送到 eventChan |
| `startNetworkMonitor(eventChan)` | 枚举活跃网卡 → 对每个网卡挂载 tc_ingress + tc_egress → 打开 ringbuf → `go readNetworkEvents()` |
| `readNetworkEvents(rd, eventChan)` | 阻塞循环：从 ringbuf 读 → 手动解析各字段 → IP/协议转换 → 组装事件 → 发送到 eventChan |
| `startCPUMonitor()` | 加载 cpu BPF 对象 → 挂载到 `sched_switch` tracepoint → 返回 true |
| `getCPUUsage()` | 从 `cpu_stats` PERCPU_ARRAY 读取各核 busy/idle 差值 → 计算百分比 |

**关键实现细节**:

- execve 事件使用 `unsafe.Pointer` 零拷贝复制：`copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)`
- network 事件使用 `binary.LittleEndian` 手动解析各字段（因其结构体有 padding）
- 所有 ringbuf 读取都在独立 goroutine 中运行，非阻塞发送到 eventChan

#### `ebpf_events.go` — 事件结构体定义

定义与 eBPF C 端对齐的 Go 结构体：

```go
type execveEvent struct {
    PID   uint32     // 对应 C: u32 pid
    PPID  uint32     // 对应 C: u32 ppid
    Comm  [16]byte   // 对应 C: char comm[16]
    Argv0 [128]byte  // 对应 C: char argv0[128]
}
// 总大小: 4+4+16+128 = 152 字节

type networkEvent struct { ... }
// 总大小: 38 字节
```

**⚠️ 必须与 C 端 struct 完全对齐，否则二进制解析出错。**

#### `network_utils.go` — 网络工具函数

| 函数 | 作用 |
|------|------|
| `ipToString(ip)` | 主机序 uint32 → 点分十进制字符串 |
| `protocolToString(p)` | 协议号 → "TCP"/"UDP"/"ICMP" |
| `getNetworkInterfaces()` | 获取所有非 lo 的 up 状态网卡 |
| `attachNetworkProgram(objs, idx, isIngress)` | 通过 `link.AttachTCX()` 挂载 tc 程序到指定网卡方向 |

#### `policy.go` — 策略控制

通过 `atomic.Bool` 维护开关状态 + 同步到 eBPF map：

| 函数 | 行为 |
|------|------|
| `init()` | 默认开启 execve + network 监控 |
| `isExecveMonitoringEnabled()` / `isNetworkMonitoringEnabled()` | 原子读开关 |
| `setExecveMonitoringEnabled(bool)` / `setNetworkMonitoringEnabled(bool)` | 写 eBPF map + 写 atomic |
| `syncExecveMonitoringMap(bool)` / `syncNetworkMonitoringMap(bool)` | 将值写入 eBPF 的 `monitoring_enabled` map |
| `updateToggleMap(target, enabled)` | 通用：向 ARRAY map 的 key=0 写入 0 或 1 |

---

### 4.5 内部包 (internal/)

#### `internal/plugin/plugin.go` — 插件系统

**设计模式**: 插件接口 + 管理器模式

**Plugin 接口**:

```go
type Plugin interface {
    Name() string
    Description() string
    Load() error      // 加载 eBPF 对象到内核
    Attach() error    // 挂载到钩子点
    Detach() error    // 卸载
    Close() error     // 清理资源
    Start(chan<- *Event) error  // 开始读取事件
}
```

**BasePlugin**: 提供 `Name()`, `Description()`, `Detach()` 的默认实现，具体插件通过嵌入 `BasePlugin` 来复用。

**Manager**: 管理一组插件，提供批量操作：`LoadAll()`, `AttachAll()`, `StartAll()`, `DetachAll()`, `CloseAll()`

**通用事件结构 Event**:

```go
type Event struct {
    Type      string                 // "execve" | "network" | "system"
    Timestamp int64                  // Unix 时间戳
    Data      map[string]interface{} // 任意数据
}
```

> **注意**: 当前项目中 `monitor_runtime.go` 的 eBPF 监控并未使用 Manager+Plugin 模式，而是直接在 main 包中管理。plugin 包是预留架构。

#### `internal/plugin/execve_plugin.go` — Execve 插件（预留）

独立实现了 `Plugin` 接口的 execve 监控插件，但当前为**占位符实现**（Load 返回 nil，Attach 检查 obj 非 nil 才工作）。实际 execve 监控由 `monitor_runtime.go` 直接管理。

#### `internal/plugin/system_plugin.go` — 系统监控插件

监控系统级指标（非 eBPF 方式）：

| 采集项 | 实现方式 |
|--------|----------|
| CPU 使用率 | 优先用 eBPF (`GetCPUUsage`)，fallback 到 `gopsutil` |
| 网络速度 | 通过 `gopsutil` 的 `net.IOCounters()` 计算字节差值/时间 |

采集周期：**每秒一次**，通过 `time.NewTicker(time.Second)` 驱动。

**`GetCPUUsage` 函数变量**: 在 `main.go` 的 `startSystemPlugin()` 中由 eBPF `getCPUUsage` 函数注入。如果 eBPF CPU 监控加载失败则为 nil，回退到 gopsutil。

#### `internal/websocket/hub.go` — WebSocket Hub

经典的多客户端 Hub 模式：

```text
Client A ──┐
Client B ──┤    register/unregister/broadcast
Client C ──┘         ↑    channels     ↓
                 ┌───────────────┐
                 │    Hub.Run()  │  (goroutine)
                 └───────────────┘
```

- **register**: 新客户端加入
- **unregister**: 客户端断开（从 map 移除，关闭 send channel）
- **broadcast**: 向所有客户端 send channel 发送消息

每个 Client 有独立的 `readPump()` 和 `writePump()` goroutine：

- `readPump`: 读取客户端消息（当前仅读取不处理，用于保活）
- `writePump`: 从 send channel 读取并 `WriteMessage`

**安全特性**:

- `CheckOrigin`: 浏览器连接仅接受同源 Origin
- `SetReadLimit(512)`: 限制读取大小防止内存攻击

#### `internal/models/event.go` — 数据模型 + SQLite

**数据模型**:

- `ExecveEvent`: pid, ppid, comm, argv0
- `NetworkEvent`: pid, src_ip, dst_ip, src_port, dst_port, protocol, direction, packet_size, comm

**数据库操作**:

| 函数 | 说明 |
|------|------|
| `InitDB()` | 打开 `sentinel.db` → `AutoMigrate` 建表 |
| `CreateEvent(event)` | 写入 execve 事件 |
| `CreateNetworkEvent(event)` | 写入 network 事件 |
| `GetRecentEvents(limit)` | 查询最近 N 条 execve 事件（按时间倒序） |
| `GetRecentNetworkEvents(limit)` | 查询最近 N 条 network 事件 |

---

### 4.6 Web 层

#### `routes.go` — HTTP/WS 路由注册

| 路由 | 方法 | 功能 |
|------|------|------|
| `/api/events` | GET | 获取最近 100 条进程事件 |
| `/api/network-events` | GET | 获取最近 100 条网络事件 |
| `/api/policy/status` | GET | 获取各监控开关状态 |
| `/api/policy/execve/:enabled` | POST | 设置 execve 监控开关 |
| `/api/policy/network/:enabled` | POST | 设置 network 监控开关 |
| `/api/processes` | GET | 获取系统进程列表 |
| `/api/process/kill/:pid` | POST | 发送 SIGTERM |
| `/api/process/kill/:pid/force` | POST | 发送 SIGKILL |
| `/ws` | GET | WebSocket 升级 |
| `/` | GET | 静态文件 → `web/dist/index.html` |
| `/*` (NoRoute) | GET | SPA fallback → `index.html` |

#### `security.go` — API 鉴权

Gin 中间件 `requireMutationAccess()`：

- **放行条件**: 请求来自 loopback 地址 **或** 携带正确 `SENTINEL_ADMIN_TOKEN`
- **Token 来源**: 环境变量 `SENTINEL_ADMIN_TOKEN`
- **Token 携带方式**: `Authorization: Bearer <token>` 或 `X-Sentinel-Token: <token>`
- **比较方式**: `subtle.ConstantTimeCompare`（时序安全）

#### `process_routes.go` — 进程管理

| 功能 | 实现 |
|------|------|
| 进程列表 | `gopsutil` 枚举进程 + 2 秒缓存 + 基于 `/proc` CPU 时间差计算 CPU% |
| 进程查杀 | `syscall.Kill(pid, SIGTERM)` / `syscall.Kill(pid, SIGKILL)` |

#### `web/dist/index.html` — 前端监控面板

单文件 SPA（约 1500 行），无构建依赖，直接由 Gin 提供静态服务。

**功能模块**:

1. **系统概览**: CPU 使用率 + 入/出站网速（实时更新）
2. **进程事件表**: execve 事件流（PID/PPID/进程名/命令行/时间）
3. **网络事件表**: 网络流量流（进程/源IP:端口 → 目的IP:端口/协议/方向/大小）
4. **进程管理器**: 系统进程列表 + Kill 按钮
5. **策略控制**: 开关 execve/network 监控

**实时通信**:

```text
WebSocket 连接 → 接收 JSON 消息 → 根据 type 字段路由:
  "execve"   → 追加到进程事件表
  "network"  → 追加到网络事件表
  "system"   → 更新 CPU/网速仪表盘
```

---

## 五、程序运行全流程

### 5.1 编译构建

虽然 `go.mod` 中没看到 `go:generate` 指令，但构建流程为：

```bash
# 1. 生成 Go 绑定（如果修改了 .c 文件）
go generate ./...

# 2. 编译
go build -o eBPF-Sentinel .

# 3. 运行（需要 root 权限加载 eBPF）
sudo ./eBPF-Sentinel
```

`bpf2go` 的工作流：

```text
ebpf/cpu.c     ──clang──→ cpu_bpfel.o     ──bpf2go──→ cpu_bpfel.go
ebpf/execve.c  ──clang──→ execve_x86_bpfel.o ──bpf2go──→ execve_x86_bpfel.go
ebpf/network.c ──clang──→ network_x86_bpfel.o ──bpf2go──→ network_x86_bpfel.go
```

### 5.2 启动时序图

```text
main()
 │
 ├─[1] models.InitDB()
 │     └─ gorm.Open(sqlite.Open("sentinel.db"))
 │     └─ db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{})
 │
 ├─[2] hub := websocket.NewHub()
 │     go hub.Run()  ──────────────────────────────┐
 │                                                  │ (goroutine)
 ├─[3] eventChan := make(chan *plugin.Event, 256)  │
 │     go dispatchPluginEvents(hub, eventChan) ────┤
 │                                                  │
 ├─[4] cpuUsageFn := startEBPFMonitors(eventChan)  │
 │     │                                            │
 │     ├─ rlimit.RemoveMemlock()                    │
 │     │                                            │
 │     ├─ startExecveMonitor(eventChan)             │
 │     │   ├─ loadExecveObjects()    → 加载到内核   │
 │     │   ├─ link.Tracepoint()      → 挂载         │
 │     │   ├─ ringbuf.NewReader()    → 打开 ringbuf │
 │     │   └─ go readExecveEvents() ───────────────┤ (goroutine)
 │     │                                            │
 │     ├─ startNetworkMonitor(eventChan)            │
 │     │   ├─ loadNetworkObjects()   → 加载到内核   │
 │     │   ├─ getNetworkInterfaces() → 枚举网卡     │
 │     │   ├─ for each iface:                       │
 │     │   │   ├─ attachNetworkProgram(ingress)     │
 │     │   │   └─ attachNetworkProgram(egress)      │
 │     │   ├─ ringbuf.NewReader()    → 打开 ringbuf │
 │     │   └─ go readNetworkEvents() ──────────────┤ (goroutine)
 │     │                                            │
 │     └─ startCPUMonitor()                         │
 │         ├─ loadCpuObjects()       → 加载到内核   │
 │         └─ link.Tracepoint()      → 挂载         │
 │         return getCPUUsage                       │
 │                                                  │
 ├─[5] startSystemPlugin(eventChan, cpuUsageFn)     │
 │     ├─ plugin.GetCPUUsage = cpuUsageFn (注入)    │
 │     └─ go systemPlugin.Start() ─────────────────┤ (goroutine)
 │                                                  │
 ├─[6] gin.Default()                                │
 │     setupRoutes(r, hub)                          │
 │     r.Run(":8080")  ← 阻塞                      │
 │                                                  │
 ▼ (程序阻塞在 HTTP 服务)                            │
                                                    │
    ┌───────────────────────────────────────────────┘
    │  后台 goroutine 持续运行:
    │  ├─ hub.Run()              → 管理 WebSocket 连接
    │  ├─ dispatchPluginEvents() → 事件：持久化 + 广播
    │  ├─ readExecveEvents()     → 持续读取 execve 事件
    │  ├─ readNetworkEvents()    → 持续读取 network 事件
    │  └─ systemPlugin.Start()   → 每秒采集系统指标
```

### 5.3 事件数据流

```text
    内核态 (eBPF)                    用户态 (Go)
    ════════════                    ═══════════

execve.c                            monitor_runtime.go
┌──────────────┐                    ┌──────────────────────┐
│tp/sys_enter_ │                    │ readExecveEvents()   │
│  execve      │──RINGBUF──→       │   解析二进制结构      │
│              │  events            │   → plugin.Event      │
└──────────────┘                    └───────┬──────────────┘
                                            │ eventChan
network.c                           ┌───────▼──────────────┐
┌──────────────┐                    │ dispatchPluginEvents │
│tc_ingress    │──RINGBUF──→       │  ├─ persistEvent()    │
│tc_egress     │  net_events       │  │   → SQLite         │
└──────────────┘                    │  └─ hub.Broadcast()  │
                                    │      → WebSocket     │
cpu.c                               └──────────────────────┘
┌──────────────┐                              │
│sched_switch  │                              │ WebSocket
│              │                              ▼
└──────────────┘                    ┌──────────────────────┐
    ↑                               │ web/dist/index.html  │
system_plugin.go 每秒读取           │  实时更新面板         │
getCPUUsage() ← PERCPU_ARRAY       └──────────────────────┘
```

---

## 六、eBPF 挂载点详解

| eBPF 程序 | 挂载类型 | 挂载点 | 触发频率 | 采集内容 |
|-----------|----------|--------|----------|----------|
| `tracepoint_execve` | Tracepoint | `syscalls:sys_enter_execve` | 每个 execve() | pid, ppid, comm, argv0 |
| `tc_ingress` | TC (TCX) | 网卡入站路径 | 每接收数据包（采样） | 五元组 + 进程 + 方向 |
| `tc_egress` | TC (TCX) | 网卡出站路径 | 每发送数据包（采样） | 五元组 + 进程 + 方向 |
| `tracepoint_sched_switch` | Tracepoint | `sched:sched_switch` | 每次上下文切换 | busy/idle 纳秒统计 |

---

## 七、Map 通信机制

| Map 名称 | 类型 | 方向 | 用途 |
|----------|------|------|------|
| `events` | RINGBUF (256KB) | eBPF → Go | execve 事件传输 |
| `net_events` | RINGBUF (256KB) | eBPF → Go | network 事件传输 |
| `cpu_stats` | PERCPU_ARRAY | eBPF ↔ Go | CPU busy/idle 统计（Go 主动读） |
| `monitoring_enabled` | ARRAY | Go → eBPF | execve 开关控制 |
| `net_monitoring_enabled` | ARRAY | Go → eBPF | network 开关控制 |
| `ip_whitelist` | HASH | Go → eBPF | IP 白名单 |
| `port_whitelist` | HASH | Go → eBPF | 端口白名单 |
| `ip_whitelist_enabled` | ARRAY | Go → eBPF | 白名单启用开关 |
| `port_whitelist_enabled` | ARRAY | Go → eBPF | 白名单启用开关 |
| `sample_counter` | PERCPU_ARRAY | eBPF 自用 | 采样计数器 |

---

## 八、文件依赖关系

```text
main.go
 ├── import "internal/models"      → event.go (InitDB, CreateEvent...)
 ├── import "internal/plugin"      → plugin.go (Event 类型, SystemMonitorPlugin)
 ├── import "internal/websocket"   → hub.go (Hub, NewHub, ServeWs)
 ├── import "github.com/gin-gonic/gin"
 ├── uses monitor_runtime.go       → startEBPFMonitors()
 ├── uses routes.go                → setupRoutes()
 ├── uses policy.go                → isExecveMonitoringEnabled()...
 └── uses security.go              → requireMutationAccess()

monitor_runtime.go
 ├── import "internal/plugin"      → Event 类型
 ├── import "github.com/cilium/ebpf/link"
 ├── import "github.com/cilium/ebpf/ringbuf"
 ├── uses execve_x86_bpfel.go      → execveObjects, loadExecveObjects()
 ├── uses network_x86_bpfel.go     → networkObjects, loadNetworkObjects()
 ├── uses cpu_bpfel.go             → cpuObjects, cpuCpuStat, loadCpuObjects()
 ├── uses ebpf_events.go           → execveEvent, networkEvent, const sizes
 ├── uses network_utils.go         → getNetworkInterfaces(), attachNetworkProgram()
 └── uses policy.go                → isExecveMonitoringEnabled()...

routes.go
 ├── import "internal/models"      → GetRecentEvents(), GetRecentNetworkEvents()
 ├── import "internal/websocket"   → hub.ServeWs()
 ├── uses policy.go                → isExecveMonitoringEnabled()...
 ├── uses security.go              → requireMutationAccess()
 └── uses process_routes.go        → registerProcessRoutes()

internal/plugin/system_plugin.go
 ├── import "github.com/shirou/gopsutil/v3/cpu"
 ├── import "github.com/shirou/gopsutil/v3/net"
 └── uses plugin.go                → Event 类型, BasePlugin, GetCPUUsage 变量
```

---

## 九、运行要求

| 条件 | 说明 |
|------|------|
| 操作系统 | Linux (eBPF 需要内核支持) |
| 内核版本 | ≥ 5.x (推荐 5.15+, 支持 CO-RE) |
| 权限 | **root** (`CAP_BPF` + `CAP_SYS_ADMIN`) |
| 内存锁定 | 需要解除 memlock 限制 (代码自动处理) |
| 端口 | 8080 (HTTP/WebSocket) |
| 环境变量 | `SENTINEL_ADMIN_TOKEN` (可选，API 鉴权) |

---

## 十、API 接口速查

```bash
# 查看 execve 事件
curl http://localhost:8080/api/events

# 查看 network 事件
curl http://localhost:8080/api/network-events

# 查看策略状态
curl http://localhost:8080/api/policy/status

# 关闭 execve 监控
curl -X POST http://localhost:8080/api/policy/execve/false

# 开启 network 监控
curl -X POST http://localhost:8080/api/policy/network/true

# 查看进程列表
curl http://localhost:8080/api/processes

# 杀死进程 (SIGTERM)
curl -X POST http://localhost:8080/api/process/kill/1234

# 强制杀死 (SIGKILL)
curl -X POST http://localhost:8080/api/process/kill/1234/force

# WebSocket 连接
websocat ws://localhost:8080/ws
```
