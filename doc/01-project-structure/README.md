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
- 初始化数据库连接
- 创建 WebSocket Hub
- 加载和挂载 eBPF 程序
- 启动事件读取循环
- 启动 HTTP 服务器
- 管理监控开关和进程缓存

**关键数据结构**:
- `execveEvent`: execve 事件结构体
- `networkEvent`: 网络事件结构体
- `execveObjs`/`networkObjs`: eBPF 对象实例
- `procCache`: 进程列表缓存（2 秒有效期）

### 1.2 go.mod / go.sum
**作用**: Go 模块依赖管理

**主要依赖**:
- `github.com/cilium/ebpf`: eBPF Go 库
- `github.com/gin-gonic/gin`: Web 框架
- `github.com/gorilla/websocket`: WebSocket 库
- `gorm.io/gorm`: ORM 框架
- `github.com/shirou/gopsutil/v3`: 网络速度采集和CPU监控回退

### 1.3 sentinel.db
**作用**: SQLite 数据库文件，存储事件数据

**包含表**:
- `execve_events`: 进程执行事件
- `network_events`: 网络流量事件

### 1.4 DOC.md
**作用**: 文档任务说明文件

### 1.5 LEARNING.md
**作用**: 项目学习指南，包含架构图和学习路径

### 1.6 Tasks.md
**作用**: 任务列表

---

## 2. ebpf/ 目录

### 2.1 execve.c
**作用**: 进程执行监控 eBPF 程序

**功能**:
- 挂载到 `sys_enter_execve` tracepoint
- 捕获进程创建事件
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
- 捕获所有 IPv4 数据包
- 解析 TCP/UDP/ICMP 协议
- 支持采样和白名单

**关键结构体**:
```c
struct net_event {
    u32 pid;                 // 进程ID
    u32 src_ip;             // 源IP地址
    u32 dst_ip;             // 目的IP地址
    u16 src_port;           // 源端口
    u16 dst_port;           // 目的端口
    u8 protocol;            // 传输层协议
    u8 direction;           // 方向
    u32 packet_size;        // 数据包大小
    char comm[16];          // 进程名
};
```

**BPF Maps**:
- `net_events`: Ring Buffer，网络事件传输
- `sample_counter`: Per-CPU Array，采样计数器
- `ip_whitelist`: Hash Map，IP 白名单
- `port_whitelist`: Hash Map，端口白名单
- `net_monitoring_enabled`: Array Map，监控开关
### 2.3 cpu.c
**作用**: CPU使用率监控 eBPF 程序

**功能**:
- 挂载到 `sched_switch` tracepoint
- 统计每个CPU核心的忙碌和空闲时间
- 通过PERCPU maps实现无锁统计
- 计算整体CPU使用率

**关键结构体**:
```c
struct cpu_stats {
    u64 busy_ns;      // 忙碌时间（纳秒）
    u64 idle_ns;      // 空闲时间（纳秒）
    u64 last_update;  // 最后更新时间戳
};
```

**BPF Maps**:
- `cpu_stats_map`: PERCPU Hash Map，存储每个CPU核心的统计信息
- `cpu_usage`: PERCPU Array，存储每个核心的CPU使用率（百分比）

### 2.4 vmlinux.h
**作用**: 内核数据结构头文件

**包含**:
- 内核结构体定义（task_struct, iphdr, tcphdr 等）
- 内核常量定义
- 用于 eBPF 程序访问内核数据

---

## 3. internal/ 目录

### 3.1 models/event.go
**作用**: 数据模型定义和数据库操作

**定义的结构体**:
- `ExecveEvent`: 进程事件模型
- `NetworkEvent`: 网络事件模型
- `ProcessNode`: 进程拓扑节点
- `NetworkConnection`: 网络连接关系

**提供的函数**:
- `InitDB()`: 初始化数据库
- `CreateEvent()`: 创建进程事件
- `GetRecentEvents()`: 获取最近事件
- `CreateNetworkEvent()`: 创建网络事件
- `GetRecentNetworkEvents()`: 获取最近网络事件
- `GetProcessTopology()`: 获取进程拓扑
- `GetNetworkTopology()`: 获取网络拓扑

### 3.2 plugin/

#### plugin.go
**作用**: 插件接口定义和管理

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
```

**提供的类型**:
- `Event`: 通用事件结构
- `BasePlugin`: 基础插件结构
- `Manager`: 插件管理器

#### execve_plugin.go
**作用**: execve 监控插件实现

**功能**:
- 封装 execve eBPF 程序
- 实现 Plugin 接口
- 从 Ring Buffer 读取事件
- 转换为通用事件格式

#### system_plugin.go
**作用**: 系统监控插件实现

**功能**:
- 采集 CPU 使用率（通过 eBPF `GetCPUUsage` 函数注入）
- 采集网络速度（使用 gopsutil 库）
- 定时发送系统指标事件
- 支持 eBPF 失败时回退到 gopsutil 方式

### 3.3 websocket/hub.go
**作用**: WebSocket 连接管理

**核心类型**:
- `Hub`: WebSocket 管理中心
- `Client`: 客户端连接

**功能**:
- 管理客户端连接（注册/注销）
- 广播消息给所有客户端
- 处理连接升级
- 读写分离的 goroutine 设计

---

## 4. web/ 目录

### 4.1 dist/index.html
**作用**: 前端页面

**功能**:
- btop 风格的实时进程监控
- 进程搜索功能
- WebSocket 实时事件接收
- 网络流量显示
- 系统指标图表
- DOM diffing 优化（避免闪烁）

---

## 5. scripts/ 目录

### 5.1 stress_test.sh
**作用**: 压力测试脚本

**功能**:
- 生成大量进程事件
- 测试系统性能
- 验证监控功能

---

## 6. 生成的文件

### 6.1 *_bpfel.go (如 execve_x86_bpfel.go)
**作用**: bpf2go 生成的 Go 绑定代码

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

**生成方式**:
- 由 bpf2go 自动编译 C 代码生成
- 嵌入到 Go 二进制中

---

## 7. 文件依赖关系

```
main.go
├── internal/models/event.go (数据库操作)
├── internal/websocket/hub.go (WebSocket)
├── internal/plugin/
│   ├── plugin.go (接口定义)
│   ├── execve_plugin.go (execve插件)
│   └── system_plugin.go (系统监控插件)
├── ebpf/execve.c → execve_x86_bpfel.go (bpf2go生成)
├── ebpf/network.c → network_bpfel_x86.go (bpf2go生成)
└── ebpf/cpu.c → cpu_bpfel.go (bpf2go生成)
```

---

## 8. 配置文件说明

本项目没有独立的配置文件，配置通过以下方式管理:

1. **监控开关**: 运行时通过 API 动态控制
2. **数据库**: SQLite 文件位置固定为 `sentinel.db`
3. **服务器端口**: 固定为 `:8080`

---

## 9. 关键路径说明

### 9.1 事件数据流路径
```
eBPF程序 → Ring Buffer → Go读取 → 数据库存储 → WebSocket广播 → 前端显示
```

### 9.2 控制流路径
```
前端请求 → Gin路由 → 策略管理 → eBPF Maps更新 → 内核生效
```

### 9.3 编译路径
```
*.c → bpf2go → *_bpfel.go + *_bpfel.o → go build → 可执行文件
```
