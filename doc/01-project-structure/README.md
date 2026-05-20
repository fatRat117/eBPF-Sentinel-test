# eBPF-Sentinel 项目结构说明

本文档详细说明项目各个文件和目录的作用。

## 目录结构总览

```
ebpf-Sentinel/
├── doc/                          # 项目文档目录 (本目录)
├── ebpf/                         # eBPF C 程序源码
├── internal/                     # 内部包
│   ├── models/                   # 数据模型
│   ├── plugin/                   # 插件系统
│   └── websocket/                # WebSocket 实现
├── web/                          # 前端资源
│   └── dist/                     # 编译后的前端文件
├── scripts/                      # 脚本文件
├── *.go                          # Go 主程序文件
├── *.c                           # eBPF C 源码
├── go.mod                        # Go 模块定义
└── *.db                          # SQLite 数据库文件
```

## 1. 根目录文件

### 1.1 main.go
**作用**: 程序入口，负责协调所有组件

**核心职责**:
- 初始化数据库连接（5 张表：execve_events、network_events、alert_events、user_configs、whitelist_rules）
- 创建 WebSocket Hub
- 创建 Plugin Manager 并注册 5 个插件（ExecvePlugin、NetworkPlugin、CPUPlugin、SystemMonitorPlugin、AlertPlugin）
- 加载持久化运行时配置（告警阈值、监控开关）
- 统一加载/挂载/启动所有插件
- 同步白名单规则到 eBPF Maps
- 启动事件分发 goroutine（dispatchPluginEvents）
- 启动 HTTP 服务器

**关键组件**:
- `plugin.Manager`: 插件生命周期管理器
- `websocket.Hub`: WebSocket 广播中心
- `dispatchPluginEvents()`: 事件分发和告警推导

### 1.2 policy.go
**作用**: 监控开关策略管理

**核心功能**:
- `isExecveMonitoringEnabled()`: 检查 execve 监控是否启用
- `setExecveMonitoringEnabled()`: 设置 execve 监控开关
- `isNetworkMonitoringEnabled()`: 检查网络监控是否启用
- `setNetworkMonitoringEnabled()`: 设置网络监控开关
- `setPolicyControls()`: 初始化插件 PolicyControl 接口
- 使用 `atomic.Bool` 作为 fallback 机制

**设计要点**:
- 通过 Plugin 的 `PolicyControl` 接口与 eBPF Maps 同步
- `atomic.Bool` fallback 确保插件未初始化时也能安全查询

### 1.3 routes.go
**作用**: HTTP API 路由注册

**核心功能**:
- `setupRoutes()`: 注册所有 API 路由
- 事件查询: `/api/events`, `/api/network-events`, `/api/alerts`
- 告警管理: `/api/alerts/:id/status` (PATCH), `/api/alert/config` (GET/POST)
- 策略控制: `/api/policy/status`, `/api/policy/execve/:enabled`, `/api/policy/network/:enabled`
- 白名单: `/api/whitelist` (委托到 whitelist_routes.go)
- 进程管理: `/api/processes`, `/api/process/kill/:pid`, `/api/process/kill/:pid/force` (委托到 process_routes.go)
- WebSocket: `/ws`
- 静态文件: `/assets`, `/` (SPA fallback)

### 1.4 security.go
**作用**: 安全中间件，控制变更操作访问权限

**核心功能**:
- `requireMutationAccess()`: Gin 中间件，保护所有 POST/PATCH/DELETE 端点
- `isLoopbackRequest()`: 检查请求是否来自 localhost
- `hasAdminToken()`: 验证 Bearer token 或 X-Sentinel-Token 头

**安全策略**:
- 本地回环请求 (localhost) → 直接放行
- 远程请求 → 需要 `SENTINEL_ADMIN_TOKEN` 环境变量配置
- Token 比较使用 `crypto/subtle.ConstantTimeCompare` 防止时序攻击
- 支持 `Authorization: Bearer <token>` 和 `X-Sentinel-Token: <token>` 两种头格式
- 仅读端点 (GET) 无需认证

### 1.5 whitelist_policy.go
**作用**: 白名单策略管理（IP、端口、可执行路径）

**核心功能**:
- `execPathWhitelistPolicy`: 可执行路径白名单策略
  - `ReloadFromDB()`: 从数据库重新加载白名单
  - `Matches(path)`: 检查路径是否匹配白名单
- `markExecveWhitelist()`: 标记白名单事件，抑制告警推导
- `syncWhitelistRules()`: 同步白名单到 eBPF Maps
- `createWhitelistRuleConsistent()`: 创建白名单规则（写入 DB → 同步 Maps → 失败回滚）
- `updateWhitelistRuleConsistent()`: 更新白名单规则（带回滚）
- `deleteWhitelistRuleConsistent()`: 删除白名单规则（带回滚）
- `normalizeWhitelistRule()`: 规范化白名单值（IP ↔ 端口转换）

**路径匹配模式**:
- 精确匹配: `/usr/bin/chmod` == `/usr/bin/chmod`
- 基础名匹配: `chmod` 匹配 `/usr/bin/chmod`
- 目录前缀: `/usr/local/bin/` 匹配 `/usr/local/bin/tool`
- 通配符: `/opt/trusted/*` 匹配 `/opt/trusted/agent`

### 1.6 whitelist_routes.go
**作用**: 白名单 REST API 路由

**核心功能**:
- `GET /api/whitelist`: 查询白名单规则（支持 type/enabled_only 过滤）
- `POST /api/whitelist`: 创建白名单规则（需要 admin token）
- `PATCH /api/whitelist/:id`: 更新白名单规则（需要 admin token）
- `DELETE /api/whitelist/:id`: 删除白名单规则（需要 admin token）

**白名单类型**:
- `ip`: IP 地址白名单（IPv4）
- `port`: 端口白名单（0-65535）
- `exec_path`: 可执行路径白名单（支持通配符）

### 1.7 process_routes.go
**作用**: 进程列表查询和进程管理

**核心功能**:
- `processSnapshotter`: 进程快照缓存器
  - 2 秒缓存有效期
  - CPU 使用率计算（基于 /proc 时间片差值）
  - 内存使用率采集
- `GET /api/processes`: 获取进程列表（含 CPU/内存信息）
- `POST /api/process/kill/:pid`: 终止进程 (SIGTERM，需要 admin token)
- `POST /api/process/kill/:pid/force`: 强制终止进程 (SIGKILL，需要 admin token)

### 1.8 config_store.go
**作用**: 运行时配置持久化

**核心功能**:
- `loadPersistedRuntimeConfig()`: 启动时从 DB 加载配置（告警配置、监控开关）
- `persistAlertConfig()`: 持久化告警配置
- `persistExecveMonitoringEnabled()`: 持久化 execve 监控开关
- `persistNetworkMonitoringEnabled()`: 持久化网络监控开关
- `updateAlertConfigConsistent()`: 更新告警配置（带回滚）
- `updateExecveMonitoringConsistent()`: 更新 execve 开关（带回滚）
- `updateNetworkMonitoringConsistent()`: 更新网络开关（带回滚）

**持久化的配置项**:
- `alert_config`: 告警阈值（CPU、内存、网速、包大小、冷却时间等）
- `execve_enabled`: execve 监控开关
- `network_enabled`: 网络监控开关

### 1.9 ebpf_events.go
**作用**: eBPF 事件结构体定义（Go 侧）

**定义的结构体**:
- `execveEvent`: 与 `ebpf/execve.c` 中的 `struct event` 对应
  - PID (uint32)、PPID (uint32)、Comm ([16]byte)、Argv0 ([128]byte)
- `networkEvent`: 与 `ebpf/network.c` 中的 `struct net_event` 对应
  - PID、SrcIP、DstIP、SrcPort、DstPort、Protocol、Direction、PacketSize、Comm

### 1.10 network_utils.go
**作用**: 网络辅助函数

**核心功能**:
- `ipToString()`: 32 位整数 IP → 点分十进制字符串
- `protocolToString()`: 协议号 → TCP/UDP/ICMP 字符串
- `getNetworkInterfaces()`: 获取所有活跃的非 loopback 网络接口
- `attachNetworkProgram()`: 挂载网络 eBPF 程序到指定接口（TCX ingress/egress）

### 1.11 whitelist_policy_test.go
**作用**: 白名单策略单元测试

**测试内容**:
- `TestExecPathPatternMatches`: 测试路径匹配逻辑
- `TestMarkExecveWhitelistSuppressesByPolicy`: 测试白名单标记功能
- `TestCreateWhitelistRuleConsistentRollsBackOnSyncFailure`: 测试创建回滚
- `TestUpdateWhitelistRuleConsistentRollsBackOnSyncFailure`: 测试更新回滚

### 1.12 go.mod / go.sum
**作用**: Go 模块依赖管理

**主要依赖**:
- `github.com/cilium/ebpf v0.16.0`: eBPF Go 库
- `github.com/gin-gonic/gin v1.12.0`: Web 框架
- `github.com/gorilla/websocket v1.5.3`: WebSocket 库
- `gorm.io/gorm v1.31.1`: ORM 框架
- `gorm.io/driver/sqlite v1.6.0`: SQLite 驱动
- `github.com/shirou/gopsutil/v3 v3.24.5`: 系统信息采集

### 1.13 sentinel.db
**作用**: SQLite 数据库文件，存储事件数据和配置

**包含 5 张表**:
- `execve_events`: 进程执行事件
- `network_events`: 网络流量事件
- `alert_events`: 告警事件（含状态跟踪）
- `user_configs`: 用户配置键值存储（告警阈值、监控开关）
- `whitelist_rules`: 白名单规则（IP/端口/可执行路径）

---

## 2. ebpf/ 目录

### 2.1 execve.c
**作用**: 进程执行监控 eBPF 程序

**功能**:
- 挂载到 `sys_enter_execve` tracepoint
- 捕获进程创建事件（PID、PPID、进程名、命令参数）
- 通过 Ring Buffer 发送事件到用户态

**关键结构体**:
```c
struct event {
    u32 pid;                    // 进程ID
    u32 ppid;                   // 父进程ID
    char comm[TASK_COMM_LEN];   // 进程名
    char argv0[MAX_ARGV_LEN];   // 执行的命令
};
```

**BPF Maps**:
- `events`: Ring Buffer，用于事件传输
- `monitoring_enabled`: Array Map，监控开关

### 2.2 network.c
**作用**: 网络流量监控 eBPF 程序

**功能**:
- 挂载到 TC (Traffic Control) ingress/egress
- 捕获 IPv4 TCP/UDP 数据包
- 解析源/目的 IP、端口、协议、方向
- 支持采样机制减少事件量
- IP/端口白名单过滤

**关键结构体**:
```c
struct net_event {
    u32 pid;                 // 进程ID
    u32 src_ip;             // 源IP地址
    u32 dst_ip;             // 目的IP地址
    u16 src_port;           // 源端口
    u16 dst_port;           // 目的端口
    u8 protocol;            // 传输层协议
    u8 direction;           // 方向 (0=ingress, 1=egress)
    u32 packet_size;        // 数据包大小
    char comm[16];          // 进程名
};
```

**BPF Maps**:
- `net_events`: Ring Buffer，网络事件传输
- `sample_counter`: Per-CPU Array，采样计数器
- `ip_whitelist`: Hash Map，IP 白名单数据
- `ip_whitelist_enabled`: Array Map，IP 白名单开关
- `port_whitelist`: Hash Map，端口白名单数据
- `port_whitelist_enabled`: Array Map，端口白名单开关
- `net_monitoring_enabled`: Array Map，监控开关

### 2.3 cpu.c
**作用**: CPU使用率监控 eBPF 程序

**功能**:
- 挂载到 `sched_switch` tracepoint
- 统计每个 CPU 核心的忙碌和空闲时间
- 通过 PERCPU maps 实现无锁统计
- 计算整体 CPU 使用率

**关键结构体**:
```c
struct cpu_stat {
    u64 busy_ns;      // 忙碌时间（纳秒）
    u64 idle_ns;      // 空闲时间（纳秒）
    u64 last_ts;      // 最后更新时间戳
    u32 is_busy;      // 当前是否 busy
};
```

**BPF Maps**:
- `cpu_stats`: PERCPU Hash Map，存储每个 CPU 核心的统计信息
- `cpu_usage`: PERCPU Array，存储每个核心的 CPU 使用率（百分比）

### 2.4 vmlinux.h
**作用**: 内核数据结构头文件

**包含**:
- 内核结构体定义（task_struct, iphdr, tcphdr 等）
- 内核常量定义
- 用于 eBPF 程序访问内核数据

---

## 3. internal/ 目录

### 3.1 models/

#### event.go
**作用**: 数据模型定义和数据库操作

**定义的结构体**:
- `ExecveEvent`: 进程事件模型（含 whitelisted 标记）
- `NetworkEvent`: 网络事件模型
- `AlertEvent`: 告警事件模型（含 rule_id、severity、source_type、message、details、status）

**提供的函数**:
- `InitDB()`: 初始化数据库，自动迁移 5 张表
- `CreateEvent()`: 创建进程事件
- `GetRecentEvents()`: 获取最近进程事件
- `CreateNetworkEvent()`: 创建网络事件
- `GetRecentNetworkEvents()`: 获取最近网络事件
- `CreateAlertEvent()`: 创建告警事件
- `GetRecentAlertEvents()`: 获取最近告警事件
- `GetRecentAlertEventsSince()`: 获取自某时间点以来的告警
- `UpdateAlertEventStatus()`: 更新告警状态
- `MarshalAlertDetails()`: 序列化告警详情

#### config.go
**作用**: 配置和白名单数据模型

**定义的结构体**:
- `UserConfig`: 键值对配置存储（key, value, timestamps）
- `WhitelistRule`: 白名单规则（type, value, enabled, timestamps）
  - 类型: `ip`, `port`, `exec_path`
  - type + value 组合唯一索引

**提供的函数**:
- `UpsertUserConfig()`: 插入或更新配置
- `GetUserConfig()`: 获取配置值
- `CreateWhitelistRule()` / `GetWhitelistRule()` / `FindWhitelistRule()`: 白名单 CRUD
- `ListWhitelistRules()`: 列出白名单规则（支持类型过滤和启用状态过滤）
- `UpdateWhitelistRule()` / `DeleteWhitelistRule()`: 更新/删除白名单规则

**WhitelistType 常量**:
- `WhitelistTypeIP = "ip"`
- `WhitelistTypePort = "port"`
- `WhitelistTypeExecPath = "exec_path"`

### 3.2 plugin/

#### plugin.go
**作用**: 插件接口定义和生命周期管理

**核心接口**:
```go
type Plugin interface {
    Name() string
    Description() string
    Load() error
    Attach() error
    Detach() error
    Close() error
    Start(eventChan chan<- *Event) error
}

type EventObserver interface {
    HandleEvent(event *Event) []*Event
}
```

**核心类型**:
- `Event`: 通用事件结构（Type、Timestamp、Data）
- `BasePlugin`: 基础插件结构（Name、Description、Objs、Links）
- `Manager`: 插件管理器

**Manager 功能**:
- `Register()`: 注册插件
- `Get()` / `List()`: 查询插件
- `Observers()`: 获取所有 EventObserver 插件
- `LoadAll()` / `AttachAll()` / `StartAll()`: 批量生命周期
- `DetachAll()` / `CloseAll()`: 批量清理

**PolicyControl 接口**:
- `IsEnabled() bool`: 检查插件是否启用
- `SetEnabled(bool) error`: 设置启用状态

#### execve_plugin.go
**作用**: execve 监控插件实现

**功能**:
- 封装 execve eBPF 程序加载/挂载/读取
- 实现 Plugin 接口 + PolicyControl 接口
- 从 Ring Buffer 读取事件，转换为通用 Event 格式
- 通过 BPFProvider 接口注入 eBPF 加载函数

#### network_plugin.go
**作用**: 网络监控插件实现

**功能**:
- 封装 network eBPF 程序加载/挂载/读取
- 支持多网卡自动发现和挂载
- IP 白名单 Map 管理 (`ReplaceIPWhitelist`)
- 端口白名单 Map 管理 (`ReplacePortWhitelist`)
- 实现 Plugin 接口 + PolicyControl 接口

#### cpu_plugin.go
**作用**: CPU 监控插件实现

**功能**:
- 封装 cpu eBPF 程序加载/挂载/读取
- 挂载到 `sched_switch` tracepoint
- 通过 PERCPU Map 获取各核心统计
- 计算总体 CPU 使用率
- 提供 `GetCPUUsage()` 方法供 SystemMonitorPlugin 调用

#### system_plugin.go
**作用**: 系统指标采集插件

**功能**:
- 采集 CPU 使用率（通过注入的 `cpuProvider` 函数，eBPF + gopsutil 回退）
- 采集内存使用率（gopsutil）
- 采集网络速度（gopsutil IOCounters，计算所有网卡的总流量差值）
- 每秒采集一次，通过 event channel 发送 `system` 类型事件

#### alert_plugin.go
**作用**: 告警推导插件

**功能**:
- 实现 `EventObserver` 接口
- 单指标告警:
  - `high_cpu_usage`: CPU 超过阈值
  - `high_memory_usage`: 内存超过阈值
  - `high_download_speed` / `high_upload_speed`: 网络速度超过阈值
  - `sensitive_command_exec`: 执行敏感命令（nc, ncat, nmap, tcpdump 等）
  - `suspicious_network_port`: 使用可疑端口（22, 23, 3389, 4444, 31337 等）
  - `large_network_packet`: 大包检测
- 关联规则（通过 correlation.go）:
  - `reverse_shell_detected`: 反弹 Shell 检测（敏感命令 + 可疑端口 + 时间窗口）
  - `data_exfil_detected`: 数据外泄检测（读取敏感路径 + 出站流量）
  - `process_chain_attack`: 进程链攻击检测（父子进程模式匹配）
- 可配置阈值 (AlertConfig): CPU 阈值、内存阈值、网速阈值、包大小限制、冷却时间、关联窗口
- 冷却机制: 每个规则键独立冷却，默认 30 秒，防止告警风暴

#### correlation.go
**作用**: 关联规则引擎

**核心组件**:
- `slidingWindow`: 滑动时间窗口事件存储（按 PID 索引）
- `eventRecord`: 事件记录结构
- 关联规则接口: `correlationRule.Name()` / `correlationRule.Match()`
- `reverseShellRule`: 敏感命令 + 可疑端口时间窗口关联
- `dataExfilRule`: 敏感路径读取 + 出站流量关联
- `processChainRule`: 进程父子链模式匹配（如 bash→python→sh）

#### types.go
**作用**: 二进制事件结构体定义

**定义的结构体**:
- `ExecveEventBinary`: 对应 `ebpf/execve.c` 的 struct event (152 字节)
- `NetworkEventBinary`: 对应 `ebpf/network.c` 的 struct net_event (38 字节，手动解析)
- `CPUStatBinary`: 对应 `ebpf/cpu.c` 的 struct cpu_stat

#### bpf_providers.go
**作用**: BPF 提供者接口

**作用**:
- 定义 `BPFProvider` 接口，用于插件注入 eBPF 加载函数
- 解耦插件与具体的 bpf2go 生成代码

#### alert_plugin_test.go
**作用**: 告警插件单元测试

### 3.3 websocket/

#### hub.go
**作用**: WebSocket 连接管理

**核心类型**:
- `Hub`: WebSocket 管理中心（clients 映射、broadcast/register/unregister 通道）
- `Client`: 客户端连接（读写分离的 goroutine 设计）

**功能**:
- 管理客户端连接（注册/注销，线程安全）
- `Broadcast()`: JSON 序列化后广播消息给所有客户端
- `ServeWs()`: HTTP 升级为 WebSocket
- Origin 检查: 浏览器连接仅接受同源 Origin
- 非阻塞发送（channel 满时丢弃）

---

## 4. web/ 目录

### 4.1 dist/index.html
**作用**: 前端单页仪表盘

**功能**:
- 实时进程监控面板
- 网络流量监控面板
- 系统指标图表（CPU、内存、网速）
- 告警中心面板
- 白名单管理界面
- 策略控制面板
- WebSocket 实时事件接收
- SPA 路由

---

## 5. scripts/ 目录

### 5.1 stress_test.sh
**作用**: 压力测试脚本

**功能**:
- 生成大量进程事件
- 测试系统性能
- 验证监控功能

### 5.2 build.sh
**作用**: 项目构建脚本

**功能**:
- 自动执行 `go generate` 生成 eBPF Go 绑定
- 编译 Go 项目
- 构建输出检查

### 5.3 watch.sh
**作用**: 文件监控自动编译

**功能**:
- 监控源文件变化
- 自动重新编译和运行
- 开发调试辅助

### 5.4 feature_test.sh
**作用**: 特性场景测试脚本（563 行）

**功能**:
- 综合场景测试运行器
- 覆盖进程事件、进程表变化、系统指标、网络速度和告警规则
- 基于场景的可扩展测试框架

---

## 6. 生成的文件

### 6.1 *_bpfel.go (如 execve_x86_bpfel.go)
**作用**: bpf2go 生成的 Go 绑定代码

**生成的文件**:
- `execve_x86_bpfel.go`: execve eBPF 程序绑定
- `network_x86_bpfel.go`: network eBPF 程序绑定
- `cpu_bpfel.go`: CPU eBPF 程序绑定

**包含**:
- eBPF 程序结构体定义
- Map 结构体定义
- 加载函数

**生成命令**:
```bash
go generate
```

### 6.2 *_bpfel.o (如 execve_x86_bpfel.o)
**作用**: 编译后的 eBPF 字节码

**生成文件**:
- `execve_x86_bpfel.o`: execve eBPF 字节码
- `network_x86_bpfel.o`: network eBPF 字节码
- `cpu_bpfel.o`: CPU eBPF 字节码

**生成方式**:
- 由 bpf2go 自动编译 C 代码生成
- 嵌入到 Go 二进制中

---

## 7. 文件依赖关系

```
main.go
├── internal/models/event.go (数据库操作 - 5 张表)
├── internal/models/config.go (配置 + 白名单规则)
├── internal/websocket/hub.go (WebSocket Hub)
├── internal/plugin/ (插件系统)
│   ├── plugin.go (Plugin + EventObserver + Manager)
│   ├── execve_plugin.go → ebpf/execve.c → execve_x86_bpfel.go
│   ├── network_plugin.go → ebpf/network.c → network_x86_bpfel.go
│   ├── cpu_plugin.go → ebpf/cpu.c → cpu_bpfel.go
│   ├── system_plugin.go (gopsutil + eBPF CPU provider)
│   ├── alert_plugin.go + correlation.go (EventObserver)
│   ├── types.go (二进制事件结构体)
│   └── bpf_providers.go (BPF 加载接口)
├── routes.go (所有 HTTP API 路由)
├── policy.go (监控开关策略)
├── security.go (安全中间件，token 认证)
├── whitelist_policy.go (白名单策略 + 同步)
├── whitelist_routes.go (白名单 REST API)
├── process_routes.go (进程查询 + 管理)
├── config_store.go (运行时配置持久化)
├── ebpf_events.go (eBPF 事件结构体)
└── network_utils.go (网络工具函数)
```

---

## 8. 配置文件说明

本项目没有独立的配置文件，配置通过以下方式管理:

1. **运行时配置持久化**: 通过 `config_store.go` 存储在 SQLite `user_configs` 表
   - 告警配置 (CPU/内存/网速阈值、冷却时间、关联窗口)
   - 监控开关 (execve_enabled、network_enabled)
2. **安全令牌**: 通过环境变量 `SENTINEL_ADMIN_TOKEN` 配置
3. **数据库**: SQLite 文件位置固定为 `sentinel.db`
4. **服务器端口**: 固定为 `:8080`

---

## 9. 关键路径说明

### 9.1 事件数据流路径
```
eBPF程序 → Ring Buffer → Plugin 读取 → Event Channel → dispatchPluginEvents()
→ 持久化 (SQLite) + WebSocket 广播 + Observer 链 (AlertPlugin 告警推导)
→ 前端显示
```

### 9.2 控制流路径
```
前端请求 → Gin路由 → 安全中间件 → 策略/白名单管理 → eBPF Maps更新/DB更新 → 内核生效
```

### 9.3 编译路径
```
*.c → bpf2go → *_bpfel.go + *_bpfel.o → go build → 可执行文件
```

### 9.4 插件生命周期
```
Register → LoadAll → AttachAll → StartAll (goroutines) → [运行] → DetachAll → CloseAll
```
