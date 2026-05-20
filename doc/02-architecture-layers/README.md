# eBPF-Sentinel 架构层级说明

本文档从抽象层次角度说明项目的架构设计。

## 架构总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           展示层 (Presentation Layer)                     │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Web Frontend (浏览器)                          │   │
│  │  - 实时事件展示  - 进程列表  - 网络流量图  - 系统指标图表          │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↑↓ WebSocket / HTTP
┌─────────────────────────────────────────────────────────────────────────┐
│                           应用层 (Application Layer)                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐   │
│  │   HTTP API      │  │  WebSocket Hub  │  │    Policy Manager       │   │
│  │  (Gin Router)   │  │  (实时推送)      │  │  (策略管理)              │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Event Processor (事件处理器)                   │   │
│  │  - 事件解析  - 数据库存储  - WebSocket广播  - 策略过滤            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↑↓ 数据通道
┌─────────────────────────────────────────────────────────────────────────┐
│                           插件层 (Plugin Layer)                           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐  ┌──────────────────┐   │
│  │  Execve Plugin   │  │ Network Plugin   │  │   CPU Plugin     │  │  System Monitor      │  │  Alert Plugin    │   │
│  │  (进程监控插件)   │  │ (网络监控插件)    │  │  (CPU监控插件)   │  │  Plugin (系统监控)    │  │  (告警推导插件)   │   │
│  │  - eBPF加载      │  │ - eBPF加载       │  │  - eBPF加载      │  │  - CPU采集           │  │  - EventObserver │   │
│  │  - 事件读取      │  │ - 事件读取       │  │  - sched_switch  │  │  - 网速采集          │  │  - 关联规则      │   │
│  │  - PolicyControl │  │ - PolicyControl  │  │  - 使用率计算    │  │  - 内存采集          │  │  - 冷却机制      │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  └──────────────────────┘  └──────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Plugin Manager (插件管理器)                    │   │
│  │  - 插件注册  - 生命周期管理  - 统一事件通道                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↑↓ Go ↔ eBPF 桥梁
┌─────────────────────────────────────────────────────────────────────────┐
│                        eBPF 运行时层 (eBPF Runtime Layer)                 │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              cilium/ebpf 库 (Go eBPF 库)                          │   │
│  │  - 对象加载  - 程序挂载  - Map操作  - Ring Buffer读取             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              bpf2go 生成代码 (Go ↔ eBPF 绑定)                     │   │
│  │  - *_bpfel.go 结构体定义  - 自动类型映射  - 字节码嵌入             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↑↓ 系统调用 / IOCTL
┌─────────────────────────────────────────────────────────────────────────┐
│                        内核层 (Kernel Layer)                              │
│  ┌─────────────────────┐  ┌─────────────────────────────────────────┐   │
│  │   eBPF 虚拟机       │  │           内核子系统                     │   │
│  │  ┌───────────────┐  │  │  ┌──────────┐ ┌──────────┐ ┌────────┐  │   │
│  │  │  BPF Bytecode │  │  │  │Tracepoint│ │   TC     │ │  Net   │  │   │
│  │  │  Verification │  │  │  │  子系统   │ │ 子系统   │ │Filter │  │   │
│  │  │  JIT Compile  │  │  │  └──────────┘ └──────────┘ └────────┘  │   │
│  │  └───────────────┘  │  └─────────────────────────────────────────┘   │
│  └─────────────────────┘                                               │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    BPF Maps (内核数据存储)                        │   │
│  │  - Ring Buffer  - Hash Map  - Array Map  - Per-CPU Array         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↑↓ 事件触发
┌─────────────────────────────────────────────────────────────────────────┐
│                        硬件/系统层 (Hardware/System Layer)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   进程执行    │  │   网络数据包  │  │   CPU 状态   │  │   网络接口   │ │
│  │  execve()   │  │   skb结构    │  │   使用率     │  │   统计      │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## 各层详细说明

### 1. 展示层 (Presentation Layer)

**职责**: 用户界面展示和交互

**组件**:
- Web 前端页面 (`web/dist/index.html`)
- btop 风格实时进程监控
- 进程搜索功能
- 网络流量监控
- 系统指标图表

**技术**:
- HTML5 / JavaScript
- WebSocket 客户端
- DOM diffing 优化（避免刷新闪烁）
- 每 5 秒轮询进程列表

**与其他层交互**:
- 通过 WebSocket 接收实时事件
- 通过 HTTP API 发送控制命令

---

### 2. 应用层 (Application Layer)

**职责**: 业务逻辑处理、数据流转、策略管理

#### 2.1 HTTP API (Gin Router)

**功能**:
- RESTful API 接口
- 事件查询 (`/api/events`, `/api/network-events`, `/api/alerts`)
- 告警管理 (`/api/alerts/:id/status`, `/api/alert/config`)
- 进程列表查询 (`/api/processes`)，带 2 秒缓存，含 CPU/内存信息
- 监控状态和策略控制 (`/api/policy/status`, `/api/policy/execve/:enabled`, `/api/policy/network/:enabled`)
- 白名单 CRUD (`/api/whitelist`)
- 进程治理 (`/api/process/kill/:pid`, `/api/process/kill/:pid/force`)
- WebSocket 实时事件流 (`/ws`)
- 静态文件服务 (`/assets`, `/`)

**代码位置**: `routes.go` 中的 `setupRoutes()`

#### 2.2 WebSocket Hub

**功能**:
- 管理客户端连接
- 广播事件到所有客户端
- 连接生命周期管理

**代码位置**: `internal/websocket/hub.go`

#### 2.3 Policy Manager (策略管理器)

**功能**:
- 监控开关控制（execve/network 独立开关）
- 白名单策略管理（IP/端口/可执行路径）
- 动态策略更新与持久化
- 策略同步到 eBPF Maps（立即生效）

**实现方式**: `policy.go` 和 `whitelist_policy.go` 中的策略函数
- `isExecveMonitoringEnabled()` / `setExecveMonitoringEnabled()`: execve 开关
- `isNetworkMonitoringEnabled()` / `setNetworkMonitoringEnabled()`: 网络开关
- `syncWhitelistRules()`: 白名单同步到 eBPF Maps
- 使用 `atomic.Bool` 作为 fallback，`PolicyControl` 接口与插件通信

#### 2.4 Event Processor (事件处理器)

**功能**:
- 统一事件分发 (`dispatchPluginEvents()`)
- 策略过滤（defense-in-depth：事件分发层二次检查开关）
- 白名单标记（抑制已白名单进程的告警推导）
- 数据库持久化（按事件类型落库）
- WebSocket 广播
- Observer 链：将事件分发给 EventObserver 插件生成衍生事件（告警）

**代码位置**: `main.go` 中的 `dispatchPluginEvents()` 和 `persistEvent()`

#### 2.5 Security Middleware (安全中间件)

**功能**:
- Token 认证中间件 (`requireMutationAccess()`)
- 本地回环 (localhost) 请求直接放行
- 远程请求需要 `SENTINEL_ADMIN_TOKEN` 环境变量配置
- Token 比较使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击
- 支持 `Authorization: Bearer <token>` 和 `X-Sentinel-Token: <token>` 两种头格式
- 仅读端点 (如 GET /api/events) 无需认证

**代码位置**: `security.go`

**保护范围**: 所有 POST/PATCH/DELETE 端点
- 策略控制: `/api/policy/execve/:enabled`, `/api/policy/network/:enabled`
- 白名单管理: `/api/whitelist` (POST/PATCH/DELETE)
- 进程管理: `/api/process/kill/:pid`, `/api/process/kill/:pid/force`
- 告警状态: `/api/alerts/:id/status`
- 告警配置: `/api/alert/config`

#### 2.6 Config Store (配置持久化)

**功能**:
- 运行时配置持久化到 SQLite `user_configs` 表
- 启动时加载: `loadPersistedRuntimeConfig()`
- 告警配置持久化（CPU/内存/网速阈值、冷却时间、关联窗口）
- 监控开关持久化（execve_enabled、network_enabled）
- 变更时写回 + 失败回滚模式

**代码位置**: `config_store.go`

**持久化的配置项**:
| 配置键 | 类型 | 说明 |
|--------|------|------|
| `alert_config` | JSON | 告警阈值等完整配置 |
| `execve_enabled` | bool | execve 监控开关 |
| `network_enabled` | bool | 网络监控开关 |

---

### 3. 插件层 (Plugin Layer)

**职责**: 统一的数据采集接口，支持多种监控类型

#### 3.1 插件接口定义

```go
type Plugin interface {
    Name() string                           // 插件名称
    Description() string                    // 插件描述
    Load() error                           // 加载资源
    Attach() error                         // 启动监控
    Detach() error                         // 停止监控
    Close() error                          // 清理资源
    Start(eventChan chan<- *Event) error   // 开始采集
}

type EventObserver interface {
    HandleEvent(event *Event) []*Event     // 观察事件，生成衍生事件
}
```

**PolicyControl 接口**:
```go
type PolicyControl interface {
    IsEnabled() bool           // 查询启用状态
    SetEnabled(bool) error     // 设置启用状态（同步到 eBPF Maps）
}
```

**代码位置**: `internal/plugin/plugin.go`

#### 3.2 Execve Plugin

**职责**: 封装 execve eBPF 程序

**功能**:
- 加载 execve eBPF 对象
- 挂载到 `sys_enter_execve` tracepoint
- 读取 Ring Buffer，转换为通用事件
- 实现 PolicyControl 接口（运行时开关）

**特点**:
- 基于 eBPF 的内核级监控
- 零开销（不使用时无性能损耗）
- 通过 BPFProvider 接口注入加载函数

#### 3.3 Network Plugin

**职责**: 封装 network eBPF 程序

**功能**:
- 加载 network eBPF 对象
- 挂载到所有非 loopback 网卡的 TC ingress/egress
- 读取网络事件
- 管理 IP/端口白名单 eBPF Maps
- 实现 PolicyControl 接口
- 采样机制减少高流量场景事件量

**特点**:
- 基于 TCX (AttachTCX) 的数据包捕获
- IP/端口白名单在内核空间过滤，零开销
- 支持多网卡自动发现

#### 3.4 CPU Plugin

**职责**: 封装 CPU eBPF 程序

**功能**:
- 加载 cpu eBPF 对象
- 挂载到 `sched_switch` tracepoint
- 通过 PERCPU Map 统计各核心 busy/idle 时间
- 计算总体 CPU 使用率
- 提供 `GetCPUUsage()` 供 SystemMonitorPlugin 调用

**特点**:
- eBPF 内核态采集，高性能
- PERCPU Map 实现无锁统计
- 追踪每次进程切换的时间分配

#### 3.5 System Monitor Plugin

**职责**: 系统指标采集

**功能**:
- CPU 使用率采集（注入 eBPF CPU Plugin，gopsutil 回退）
- 内存使用率采集（gopsutil VirtualMemory）
- 网络速度计算（gopsutil IOCounters，所有网卡累计流量差值）
- 每秒采集一次

**特点**:
- CPU 监控优先使用 eBPF，失败时自动回退到 gopsutil
- 内存和网络速度使用 gopsutil 用户态采集

#### 3.6 Alert Plugin

**职责**: 安全与健康告警推导

**功能**:
- 实现 `EventObserver` 接口，观察所有插件事件
- 单指标告警：高 CPU、高内存、高网速、敏感命令、可疑端口、大包
- 关联规则：反弹 Shell、数据外泄、进程链攻击
- 可配置阈值（通过 `/api/alert/config` API）
- 冷却机制：每个规则键独立冷却（默认 30 秒）
- 告警状态管理：active → resolved/terminated/exited/failed/ignored

**代码位置**: `internal/plugin/alert_plugin.go` + `internal/plugin/correlation.go`

#### 3.7 插件管理器

**职责**: 统一管理所有插件

**功能**:
- 插件注册（Register）
- 批量加载/挂载 (LoadAll / AttachAll)
- 批量启动 (StartAll)，每个插件独立 goroutine
- Observers()：获取所有 EventObserver 插件
- 生命周期管理 (DetachAll / CloseAll)

---

### 4. eBPF 运行时层 (eBPF Runtime Layer)

**职责**: Go 与 eBPF 内核程序的桥梁

#### 4.1 cilium/ebpf 库

**功能**:
- eBPF 对象加载
- 程序挂载到内核钩子
- Map 读写操作
- Ring Buffer 读取

**关键类型**:
- `ebpf.CollectionSpec`: eBPF 集合规范
- `ebpf.Program`: eBPF 程序
- `ebpf.Map`: BPF Map
- `ringbuf.Reader`: Ring Buffer 读取器
- `link.Link`: 挂载点链接

#### 4.2 bpf2go 生成代码

**功能**:
- 将 C 结构体映射到 Go 结构体
- 嵌入编译后的 eBPF 字节码
- 自动生成加载函数

**生成文件**:
- `execve_x86_bpfel.go` / `execve_x86_bpfel.o`
- `network_x86_bpfel.go` / `network_x86_bpfel.o`
- `cpu_bpfel.go` / `cpu_bpfel.o`

---

### 5. 内核层 (Kernel Layer)

**职责**: 实际的数据采集和过滤

#### 5.1 eBPF 虚拟机

**组件**:
- **Verifier**: 验证 eBPF 程序安全性
- **JIT Compiler**: 将字节码编译为机器码
- **BPF Maps**: 内核数据存储

#### 5.2 内核子系统

**Tracepoint 子系统**:
- 内核预定义的跟踪点
- 稳定的 ABI 接口
- 用于系统调用跟踪 (`sys_enter_execve`) 和调度事件跟踪 (`sched_switch`)

**TC (Traffic Control) 子系统**:
- 网络流量控制
- 数据包过滤和分类
- 支持 ingress/egress

**Netfilter 子系统**:
- 网络包过滤框架
- 与 TC 配合使用

#### 5.3 BPF Maps

**类型**:
- `BPF_MAP_TYPE_RINGBUF`: 环形缓冲区，高效事件传输
- `BPF_MAP_TYPE_HASH`: 哈希表，IP/端口白名单存储（network.c）
- `BPF_MAP_TYPE_ARRAY`: 数组，开关状态
- `BPF_MAP_TYPE_PERCPU_ARRAY`: Per-CPU 数组，采样计数器

---

### 6. 硬件/系统层 (Hardware/System Layer)

**职责**: 实际的事件源

#### 6.1 进程执行
- `execve()` 系统调用
- 进程创建和替换
- 触发 tracepoint

#### 6.2 网络数据包
- 网卡接收/发送的数据包
- `sk_buff` 结构体
- 经过 TC 钩子

#### 6.3 CPU 状态
- CPU 时间片统计
- `/proc/stat` 信息
- eBPF tracepoint 采集 (gopsutil 回退)

#### 6.4 网络接口
- 网卡统计信息
- 流量计数器
- `/proc/net/dev`

---

## 层级间数据流

### 事件数据流 (上行)

```
硬件事件 → 内核钩子 → eBPF程序 → BPF Maps → Go程序 → 数据库 → WebSocket → 前端
```

1. **硬件层**: 进程执行 / 网络包到达
2. **内核层**: 触发 tracepoint / TC 钩子
3. **eBPF层**: eBPF 程序执行，写入 Ring Buffer
4. **运行时层**: Go 程序读取 Ring Buffer
5. **应用层**: 解析事件，存储数据库，广播 WebSocket
6. **展示层**: 前端接收并展示

### 控制流 (下行)

```
前端 → HTTP API → Policy Manager → eBPF Maps → 内核生效
```

1. **展示层**: 用户操作前端界面
2. **应用层**: HTTP API 接收请求
3. **应用层**: Policy Manager 更新状态
4. **运行时层**: 写入 BPF Maps
5. **内核层**: eBPF 程序读取 Maps，调整行为

---

## 层级设计优势

### 1. 关注点分离
- 每层只负责特定职责
- 便于独立开发和测试
- 降低复杂度

### 2. 可扩展性
- 插件层支持新增监控类型
- 应用层支持新增 API
- 展示层支持新增视图

### 3. 可替换性
- 可以替换前端框架
- 可以替换数据库
- 可以替换 eBPF 库

### 4. 性能优化
- 内核层高效采集
- 运行时层零拷贝
- 应用层异步处理

---

## 与其他架构模式的对比

### vs 单体架构
- 本架构分层清晰，便于维护
- 插件系统支持功能扩展

### vs 微服务架构
- 本架构是单进程多 goroutine
- 更低的通信开销
- 更简单的部署

### vs 传统 Agent 架构
- eBPF 替代内核模块
- 更安全，无需编译内核
- 动态加载卸载
