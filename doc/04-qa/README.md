# eBPF-Sentinel Q&A

本文档回答关于 eBPF-Sentinel 的常见问题。

---

## Q1: 数据如何流动?

### 答案

eBPF-Sentinel 的数据流动分为两个方向：

#### 1. 事件数据流（上行：内核 → 用户态 → 前端）

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  内核事件源  │ → │  eBPF程序   │ → │  Ring Buffer│ → │  Go程序读取  │
│             │    │             │    │             │    │             │
│ • execve()  │    │ • 采集数据   │    │ • 异步队列   │    │ • 解析事件   │
│ • 网络包    │    │ • 写入Map   │    │ • 零拷贝    │    │ • 存储数据库 │
└─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘
                                                                 │
                    ┌─────────────┐    ┌─────────────┐          │
                    │   前端展示   │ ← │ WebSocket   │ ←────────┘
                    │             │    │   广播      │
                    │ • 实时事件   │    │             │
                    │ • 历史查询   │    │ • JSON序列化 │
                    └─────────────┘    └─────────────┘
```

**详细流程**:

1. **内核事件触发**
   - 进程调用 `execve()` 系统调用
   - 网络数据包经过网卡

2. **eBPF 程序执行**
   - 挂载的 eBPF 程序被触发
   - 采集相关信息（PID、进程名、IP、端口等）
   - 将事件写入 Ring Buffer

3. **用户态读取**
   - Go 程序通过 `ringbuf.Reader` 读取
   - 解析二进制数据为结构体
   - 检查监控开关

4. **数据存储**
   - 使用 GORM 写入 SQLite
   - 支持历史查询

5. **实时推送**
   - 通过 WebSocket Hub 广播
   - 所有连接的客户端接收

#### 2. 控制流（下行：前端 → 用户态 → 内核）

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   前端操作   │ → │  HTTP API   │ → │ Policy管理  │ → │  更新BPF Map │
│             │    │             │    │             │    │             │
│ • 开关监控  │    │ • 接收请求   │    │ • 更新状态   │    │ • 立即生效   │
│ • 查询进程  │    │ • 验证参数   │    │ • 同步Maps   │    │ • 无需重启   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**详细流程**:

1. **用户操作**
   - 前端发送 HTTP 请求
   - 例如：查询进程列表、关闭监控

2. **API 处理**
   - Gin 路由处理请求
   - 验证参数

3. **策略更新**
   - 更新内存中的策略状态
   - 同步到 BPF Maps

4. **内核生效**
   - eBPF 程序读取更新后的 Map
   - 立即应用新策略

---

## Q2: 内核态在做什么?

### 答案

内核态主要执行 eBPF 程序，负责高效的数据采集和初步过滤。

#### 1. execve 监控（`ebpf/execve.c`）

**挂载点**: `tp/syscalls/sys_enter_execve`

**执行流程**:
```c
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 1. 检查监控开关
    if (!is_monitoring_enabled())
        return 0;
    
    // 2. 在 Ring Buffer 预留空间
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    
    // 3. 采集数据
    e->pid = bpf_get_current_pid_tgid() >> 32;  // 获取PID
    bpf_get_current_comm(&e->comm, sizeof(e->comm));  // 获取进程名
    
    // 4. 读取系统调用参数
    bpf_probe_read_user_str(&e->argv0, sizeof(e->argv0), filename);
    
    // 5. 提交事件
    bpf_ringbuf_submit(e, 0);
}
```

**内核态职责**:
- 捕获所有 execve 系统调用
- 采集进程信息（PID、PPID、进程名、命令参数）
- 检查监控开关
- 通过 Ring Buffer 发送事件

#### 2. 网络监控（`ebpf/network.c`）

**挂载点**: `tc` (Traffic Control) ingress/egress

**执行流程**:
```c
int tc_ingress(struct __sk_buff *skb)
{
    // 1. 解析数据包
    struct ethhdr *eth = data;
    struct iphdr *ip = data + ETH_HLEN;
    
    // 2. 检查是否为 IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;
    
    // 3. 采样检查（减少事件量）
    if (!should_sample(direction))
        return 0;
    
    // 4. 解析 IP 和端口
    src_ip = get_src_ip(ip_data, data_end);
    dst_ip = get_dst_ip(ip_data, data_end);
    src_port = get_src_port(transport_data, data_end, protocol);
    
    // 5. 白名单检查
    if (!is_ip_whitelisted(src_ip))
        return 0;
    
    // 6. 提交事件
    bpf_ringbuf_submit(e, 0);
}
```

**内核态职责**:
- 捕获所有经过网卡的数据包
- 解析以太网头、IP 头、TCP/UDP 头
- 实现采样机制（每 N 个包取 1 个）
- IP 和端口白名单过滤
- 区分入站/出站流量

#### 3. BPF Maps 的作用

**Maps 是内核态和用户态共享的数据结构**:

| Map 类型 | 用途 | 访问方向 |
|---------|------|---------|
| Ring Buffer | 事件传输 | 内核→用户 |
| Array Map | 开关状态 | 双向 |
| Per-CPU Array | 采样计数器 | 内核内部 |

**内核态操作 Maps**:
```c
// 读取配置
u32 *value = bpf_map_lookup_elem(&monitoring_enabled, &key);

// 写入事件
bpf_ringbuf_reserve(&events, sizeof(*e), 0);
bpf_ringbuf_submit(e, 0);
```

#### 4. 内核态的优势

1. **高性能**
   - 直接在内核空间执行
   - 无需用户态/内核态切换
   - JIT 编译为机器码

2. **安全性**
   - Verifier 验证程序安全性
   - 防止内核崩溃
   - 资源使用限制

3. **灵活性**
   - 动态加载/卸载
   - 运行时更新配置
   - 不影响系统运行

---

## Q3: 用户态在做什么?

### 答案

用户态负责 eBPF 程序的生命周期管理、数据处理、存储和展示。

#### 1. eBPF 程序管理

**加载**:
```go
// 1. 移除内存限制
rlimit.RemoveMemlock()

// 2. 加载 eBPF 对象
execveObjs = &execveObjects{}
loadExecveObjects(execveObjs, nil)
```

**挂载**:
```go
// 挂载到 tracepoint
execveTp, _ := link.Tracepoint("syscalls", "sys_enter_execve", 
                               execveObjs.TracepointExecve, nil)

// 挂载到 TC
ingressLink, _ := link.AttachTCX(link.TCXOptions{
    Interface: ifaceIdx,
    Program:   objs.TcIngress,
    Attach:    ebpf.AttachTCXIngress,
})
```

**生命周期**:
```
加载 → 挂载 → 运行 → 卸载 → 清理
```

#### 2. 事件处理

**读取事件**:
```go
// 打开 Ring Buffer
execveRd, _ := ringbuf.NewReader(execveObjs.Events)

// 读取循环
for {
    record, _ := execveRd.Read()
    
    // 解析二进制数据
    var event execveEvent
    copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)
    
    // 转换为字符串
    comm := string(bytes.Trim(event.Comm[:], "\x00"))
}
```

**策略过滤**:
```go
// 检查监控开关
if !isExecveMonitoringEnabled() {
    continue
}
```

#### 3. 数据存储

**数据库操作**:
```go
// 初始化
db, _ := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{})

// 创建记录
dbEvent := &models.ExecveEvent{
    PID:   event.PID,
    PPID:  event.PPID,
    Comm:  comm,
    Argv0: argv0,
}
models.CreateEvent(dbEvent)
```

**存储内容**:
- 进程事件：PID、PPID、进程名、命令、时间戳
- 网络事件：PID、IP、端口、协议、方向、包大小

#### 4. 实时推送

**WebSocket 广播**:
```go
// 创建 Hub
hub := websocket.NewHub()
go hub.Run()

// 广播事件
hub.Broadcast(map[string]interface{}{
    "type": "execve",
    "data": map[string]interface{}{
        "pid":   event.PID,
        "comm":  comm,
        "argv0": argv0,
    },
})
```

#### 5. HTTP API

**提供的接口**:

| 接口 | 方法 | 功能 | 认证 |
|------|------|------|------|
| `/api/events` | GET | 获取进程事件 | 无 |
| `/api/network-events` | GET | 获取网络事件 | 无 |
| `/api/alerts` | GET | 获取告警事件（支持 history 参数） | 无 |
| `/api/alerts/:id/status` | PATCH | 更新告警状态 | Admin Token |
| `/api/alert/config` | GET | 获取告警配置 | 无 |
| `/api/alert/config` | POST | 更新告警配置 | Admin Token |
| `/api/processes` | GET | 获取进程列表（含CPU/内存） | 无 |
| `/api/policy/status` | GET | 获取监控状态 | 无 |
| `/api/policy/execve/:enabled` | POST | 切换 execve 监控 | Admin Token |
| `/api/policy/network/:enabled` | POST | 切换网络监控 | Admin Token |
| `/api/whitelist` | GET | 查询白名单规则 | 无 |
| `/api/whitelist` | POST | 创建白名单规则 | Admin Token |
| `/api/whitelist/:id` | PATCH | 更新白名单规则 | Admin Token |
| `/api/whitelist/:id` | DELETE | 删除白名单规则 | Admin Token |
| `/api/process/kill/:pid` | POST | 终止进程 (SIGTERM) | Admin Token |
| `/api/process/kill/:pid/force` | POST | 强制终止进程 (SIGKILL) | Admin Token |
| `/ws` | WebSocket | 实时事件流 | 无 |
| `/assets` | Static | 前端静态资源 | 无 |
| `/` | Static | 前端 SPA 入口 | 无 |

#### 6. 插件系统

**插件接口**:
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

**已注册的 5 个插件**:
- **ExecvePlugin**: eBPF 进程执行监控（sys_enter_execve tracepoint）
- **NetworkPlugin**: eBPF 网络流量监控（TC ingress/egress），含 IP/端口白名单
- **CPUPlugin**: eBPF CPU 使用率监控（sched_switch tracepoint）
- **SystemMonitorPlugin**: 系统指标采集（CPU 注入、内存 gopsutil、网速 gopsutil）
- **AlertPlugin**: EventObserver，安全与健康告警推导

#### 7. 用户态的优势

1. **灵活性**
   - 复杂的业务逻辑
   - 动态策略更新
   - 丰富的库支持

2. **可维护性**
   - Go 代码易于编写和调试
   - 完善的错误处理
   - 单元测试支持

3. **功能丰富**
   - 数据库存储
   - Web 服务
   - 进程管理

---

## Q4: 画出数据流（文本图）

### 答案

#### 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              用户空间 (User Space)                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Web Frontend                                │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │    │
│  │  │  进程监控   │  │  网络监控   │  │  系统指标   │  │  拓扑图   │  │    │
│  │  │   面板     │  │   面板     │  │   面板     │  │   面板    │  │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘  │    │
│  │         │                │                │               │        │    │
│  │         └────────────────┴────────────────┴───────────────┘        │    │
│  │                              │                                      │    │
│  │                    WebSocket │ HTTP                                │    │
│  └──────────────────────────────┼──────────────────────────────────────┘    │
│                                 │                                           │
│  ┌──────────────────────────────┼──────────────────────────────────────┐    │
│  │                         Go 后端                                      │    │
│  │  ┌───────────────────────────┼──────────────────────────────────┐  │    │
│  │  │      HTTP API (Gin)       │                                  │  │    │
│  │  │  ┌─────────┐ ┌─────────┐ │ ┌─────────┐ ┌─────────┐          │  │    │
│  │  │  │  事件   │ │  策略   │ │ │  进程   │ │  查询   │          │  │    │
│  │  │  │  接口   │ │  接口   │ │ │  治理   │ │  接口   │          │  │    │
│  │  │  └────┬────┘ └────┬────┘ │ └────┬────┘ └────┬────┘          │  │    │
│  │  │       └───────────┴──────┴──────┴───────────┘                │  │    │
│  │  │                       │                                      │  │    │
│  │  └───────────────────────┼──────────────────────────────────────┘  │    │
│  │                          │                                          │    │
│  │  ┌───────────────────────┼──────────────────────────────────────┐  │    │
│  │  │              Event Processor (事件处理器)                      │  │    │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │  │    │
│  │  │  │  解析   │→ │  过滤   │→ │  存储   │→ │  广播   │          │  │    │
│  │  │  │  事件   │  │  策略   │  │  数据库 │  │ WebSocket│         │  │    │
│  │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘          │  │    │
│  │  └──────────────────────────────────────────────────────────────┘  │    │
│  │                          ▲                                          │    │
│  │                          │                                          │    │
│  │  ┌───────────────────────┴──────────────────────────────────────┐  │    │
│  │  │                    Plugin Layer (插件层)                       │  │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │    │
│  │  │  │ Execve      │  │ Network     │  │ System Monitor      │   │  │    │
│  │  │  │ Plugin      │  │ Plugin      │  │ Plugin              │   │  │    │
│  │  │  │             │  │             │  │                     │   │  │    │
│  │  │  │ • 加载eBPF │  │ • 加载eBPF │  │ • CPU采集           │   │  │    │
│  │  │  │ • 读取事件 │  │ • 读取事件 │  │ • 网速采集          │   │  │    │
│  │  │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘   │  │    │
│  │  │         │                │                    │              │  │    │
│  │  │         └────────────────┴────────────────────┘              │  │    │
│  │  │                          │                                   │  │    │
│  │  │              Ring Buffer │ Read                              │  │    │
│  │  └──────────────────────────┼───────────────────────────────────┘  │    │
│  │                             │                                       │    │
│  │  ┌──────────────────────────┼───────────────────────────────────┐  │    │
│  │  │           cilium/ebpf (eBPF Go库)                            │  │    │
│  │  │  • 加载eBPF对象  • 挂载程序  • 操作Maps  • 读取RingBuffer    │  │    │
│  │  └──────────────────────────┼───────────────────────────────────┘  │    │
│  └─────────────────────────────┼──────────────────────────────────────┘    │
│                                │ syscall / ioctl                           │
└────────────────────────────────┼───────────────────────────────────────────┘
                                 ↓
┌────────────────────────────────┼───────────────────────────────────────────┐
│                              内核空间 (Kernel Space)                        │
│                                │                                           │
│  ┌─────────────────────────────┼───────────────────────────────────────┐   │
│  │                      eBPF 虚拟机                                       │   │
│  │  ┌──────────────────────────┼───────────────────────────────────┐   │   │
│  │  │         Verifier         │  验证程序安全性                    │   │   │
│  │  │         JIT Compiler     │  编译为机器码                      │   │   │
│  │  └──────────────────────────┼───────────────────────────────────┘   │   │
│  └─────────────────────────────┼───────────────────────────────────────┘   │
│                                │                                           │
│  ┌─────────────────────────────┼───────────────────────────────────────┐   │
│  │                    eBPF 程序                                           │   │
│  │  ┌──────────────────────────┼───────────────────────────────────┐   │   │
│  │  │     execve.c             │     network.c                     │   │   │
│  │  │  ┌──────────────────┐    │    ┌──────────────────┐            │   │   │
│  │  │  │ tracepoint_execve│    │    │  tc_ingress      │            │   │   │
│  │  │  │                  │    │    │  tc_egress       │            │   │   │
│  │  │  │ 1. 采集PID/Comm  │    │    │                  │            │   │   │
│  │  │  │ 2. 写RingBuffer │    │    │ 1. 解析数据包    │            │   │   │
│  │  │  └────────┬─────────┘    │    │ 2. 采样检查      │            │   │   │
│  │  │  └────────┬─────────┘    │    └────────┬─────────┘            │   │   │
│  │  │           │              │             │                      │   │   │
│  │  │           └──────────────┴─────────────┘                      │   │   │
│  │  │                          │                                    │   │   │
│  │  │              ┌───────────┴───────────┐                        │   │   │
│  │  │              ↓                       ↓                        │   │   │
│  │  │  ┌─────────────────────┐  ┌─────────────────────┐            │   │   │
│  │  │  │   BPF Maps          │  │   BPF Maps          │            │   │   │
│  │  │  │  • events (RingBuf) │  │  • net_events       │            │   │   │
│  │  │  │  • monitoring_en    │  │  • sample_counter   │            │   │   │
│  │  │  │                    │  │  • ip_whitelist     │            │   │   │
│  │  │  └─────────────────────┘  └─────────────────────┘            │   │   │
│  │  └──────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      内核子系统 (Hook Points)                        │   │
│  │                                                                     │   │
│  │    Tracepoint: syscalls:sys_enter_execve  ←── execve.c 挂载        │   │
│  │         ↑                                                          │   │
│  │         │    进程调用 execve()                                      │   │
│  │    ┌────┴────┐                                                     │   │
│  │    │  进程   │                                                     │   │
│  │    └─────────┘                                                     │   │
│  │                                                                     │   │
│  │    TC Ingress/Egress  ←── network.c 挂载                           │   │
│  │         ↑                                                          │   │
│  │         │    网络数据包                                             │   │
│  │    ┌────┴────┐                                                     │   │
│  │    │  网卡   │                                                     │   │
│  │    └─────────┘                                                     │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 事件数据流时序图

```
时间 →

进程执行 ls 命令:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

User Space          Kernel Space                    User Space
(进程)              (eBPF)                          (Sentinel)
  │                      │                               │
  │  execve("/bin/ls")   │                               │
  │─────────────────────→│                               │
  │                      │                               │
  │              ┌───────┴───────┐                       │
  │              │ tracepoint    │                       │
  │              │ sys_enter_    │                       │
  │              │ execve        │                       │
  │              └───────┬───────┘                       │
  │                      │                               │
│                      │ 1. 采集 PID/Comm/Args         │
│                      │ 2. 写入 Ring Buffer           │
  │                      │                               │
  │                      │◄────── bpf_ringbuf_submit ───→│
  │                      │                               │
  │                      │◄──────────────────────────────│ ringbuf.Read()
  │                      │                               │
  │                      │                               │ 4. 解析事件
  │                      │                               │ 5. 存储数据库
  │                      │                               │ 6. WebSocket广播
  │                      │                               │
  │◄────────────────────────────────────────────────────│
  │                      │                               │ JSON {"type":"execve"}
  │              (浏览器显示新事件)                       │
  │                      │                               │

网络数据包到达:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

网卡                Kernel Space                    User Space
  │                      │                               │
  │  数据包              │                               │
  │─────────────────────→│                               │
  │                      │                               │
  │              ┌───────┴───────┐                       │
  │              │   TC Hook     │                       │
  │              │  (ingress)    │                       │
  │              └───────┬───────┘                       │
  │                      │                               │
  │                      │ 1. 解析 IP/TCP/UDP            │
  │                      │ 2. 采样检查                   │
  │                      │ 3. 写入 Ring Buffer           │
  │                      │                               │
  │                      │◄────── bpf_ringbuf_submit ───→│
  │                      │                               │
  │                      │◄──────────────────────────────│ ringbuf.Read()
  │                      │                               │
  │                      │                               │ 4. 解析事件
  │                      │                               │ 5. 存储数据库
  │                      │                               │ 6. WebSocket广播
  │                      │                               │
  │◄────────────────────────────────────────────────────│
  │                      │                               │ JSON {"type":"network"}
  │              (浏览器显示新事件)                       │
  │                      │                               │
```

#### 控制流时序图

```
用户查询进程列表:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

浏览器              Go后端              进程缓存            /proc
  │                    │                    │                    │
  │ GET /api/processes │                    │                    │
  │───────────────────→│                    │                    │
  │                    │                    │                    │
  │                    │ 检查缓存            │                    │
  │                    │───────────────────→│                    │
  │                    │                    │                    │
  │                    │                    │ 返回缓存数据        │
  │                    │◄───────────────────│                    │
  │                    │                    │                    │
  │                    │ (如果缓存过期)      │                    │
  │                    │ 读取 /proc          │                    │
  │                    │───────────────────────────────────────────→│
  │                    │                    │                    │
  │                    │                    │                    │ 返回进程信息
  │                    │◄──────────────────────────────────────────│
  │                    │                    │                    │
  │                    │ 更新缓存            │                    │
  │                    │───────────────────→│                    │
  │                    │                    │                    │
  │ 200 OK             │                    │                    │
  │ (进程列表 JSON)     │                    │                    │
  │◄───────────────────│                    │                    │
  │                    │                    │                    │
```

---

## Q5: 这个工具在监控什么?

### 答案

eBPF-Sentinel 监控三类系统活动：

#### 1. 进程活动监控

**监控内容**:
- 进程创建事件（execve 系统调用）
- 进程 ID (PID)
- 父进程 ID (PPID)
- 进程名（可执行文件名）
- 执行的命令行参数
- 事件发生时间

**监控点**: `syscalls:sys_enter_execve` tracepoint

**用途**:
- 发现异常进程启动
- 追踪进程父子关系
- 审计命令执行历史
- 检测恶意软件执行

**示例事件**:
```json
{
  "type": "execve",
  "data": {
    "pid": 12345,
    "ppid": 1000,
    "comm": "curl",
    "argv0": "/usr/bin/curl"
  }
}
```

#### 2. 网络流量监控

**监控内容**:
- 所有 IPv4 数据包
- 源 IP 地址和目的 IP 地址
- 源端口和目的端口
- 传输层协议（TCP/UDP/ICMP）
- 流量方向（入站/出站）
- 数据包大小
- 关联的进程

**监控点**: TC (Traffic Control) ingress/egress

**用途**:
- 网络流量分析
- 异常连接检测
- 进程网络行为分析
- 数据泄露检测

**示例事件**:
```json
{
  "type": "network",
  "data": {
    "pid": 12345,
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "protocol": "UDP",
    "direction": "egress",
    "packet_size": 65,
    "comm": "curl"
  }
}
```

**采样机制**:
- 默认每 100 个包采样 1 个
- 减少高流量场景下的性能开销
- 仍能保证检测到流量模式

#### 3. 系统指标监控

**监控内容**:
- CPU 使用率（百分比，eBPF sched_switch tracepoint + gopsutil 回退）
- 内存使用率（百分比，gopsutil VirtualMemory）
- 网络入站速度（KB/s）
- 网络出站速度（KB/s）

**监控方式**: eBPF tracepoint sched_switch (CPU 优先) 或 gopsutil 库（CPU 回退/内存/网络速度）

**用途**:
- 系统负载监控
- 资源使用趋势
- 性能瓶颈分析
- 异常资源消耗检测

**示例事件**:
```json
{
  "type": "system",
  "data": {
    "cpu_usage": "23.5",
    "memory_usage": "67.2",
    "net_speed_in": "150.2",
    "net_speed_out": "45.8"
  }
}
```

#### 4. 安全告警监控

**监控内容**:
- 单指标告警：CPU/内存/网速超阈值、敏感命令执行（nc/ncat/nmap/tcpdump 等）、可疑端口连接（22/23/3389/4444/31337）、大包传输
- 关联规则告警：反弹 Shell 检测（敏感命令 + 可疑端口）、数据外泄检测（敏感文件读取 + 出站流量）、进程链攻击检测（父子进程模式匹配）

**用途**:
- 实时安全威胁检测
- 异常行为关联分析
- 攻击链重建
- 告警状态跟踪（active → resolved/terminated/exited/failed/ignored）

**示例事件**:
```json
{
  "type": "alert",
  "data": {
    "rule_id": "reverse_shell_detected",
    "severity": "critical",
    "source_type": "network",
    "message": "疑似反弹 Shell：进程 ncat(PID=12345) 在执行后 0.5 秒使用了可疑端口 4444",
    "details": { "pid": 12345, "comm": "ncat", "port": 4444 },
    "status": "active"
  }
}
```

#### 4. 数据关联分析

**进程-网络关联**:
```
进程 curl (PID: 12345)
    ↓
发起网络连接
    ↓
8.8.8.8:53 (DNS查询)
```

**时间线分析**:
```
T+0ms:  进程 bash 启动 curl
T+1ms:  curl 发起 DNS 查询
T+5ms:  curl 建立 TCP 连接
T+10ms: curl 发送 HTTP 请求
```

#### 5. 监控能力总结

| 监控类型 | 数据来源 | 实时性 | 性能开销 |
|---------|---------|--------|---------|
| 进程监控 | eBPF/tracepoint | 实时 | 极低 |
| 网络监控 | eBPF/TC | 实时 | 低（采样） |
| CPU 监控 | eBPF/sched_switch | 实时 | 极低 |
| 内存监控 | gopsutil | 1秒间隔 | 极低 |
| 网速监控 | gopsutil | 1秒间隔 | 极低 |
| 告警监控 | EventObserver | 实时 | 极低 |

#### 6. 典型使用场景

**安全监控**:
- 检测未授权进程启动
- 发现异常网络连接
- 追踪攻击者行为

**运维监控**:
- 服务启动监控
- 网络流量分析
- 资源使用趋势

**故障排查**:
- 进程启动顺序
- 网络连接追踪
- 性能瓶颈定位

---

## Q6: eBPF 程序如何挂载，挂载在哪?

### 答案

eBPF-Sentinel 使用多种挂载点（Hook Points）来监控系统活动。

#### 1. 挂载点类型总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        eBPF 挂载点类型                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│  │ Tracepoint  │    │   Kprobe    │    │    TC       │                 │
│  │             │    │             │    │             │                 │
│  │ 内核预定义   │    │ 内核函数    │    │ 流量控制    │                 │
│  │ 稳定接口    │    │ 动态挂载    │    │ 网络包处理  │                 │
│  │             │    │             │    │             │                 │
│  │ ✓ execve.c │    │ 可选方案    │    │ ✓ network.c │                 │
│  └─────────────┘    └─────────────┘    └─────────────┘                 │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│  │    XDP      │    │  Uprobe     │    │  Kretprobe  │                 │
│  │             │    │             │    │             │                 │
│  │ 网卡驱动层  │    │ 用户态函数  │    │ 内核函数返回│                 │
│  │ 最高性能    │    │ 应用监控    │    │ 结果监控    │                 │
│  │             │    │             │    │             │                 │
│  │ 未来扩展    │    │ 未来扩展    │    │ 未来扩展    │                 │
│  └─────────────┘    └─────────────┘    └─────────────┘                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 2. execve 监控挂载

**挂载点**: `tp/syscalls/sys_enter_execve`

**类型**: Tracepoint

**代码**:
```c
SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 处理逻辑
}
```

**Go 挂载代码**:
```go
execveTp, err := link.Tracepoint(
    "syscalls",                    // 子系统
    "sys_enter_execve",           // 跟踪点名称
    execveObjs.TracepointExecve,  // eBPF 程序
    nil,                          // 选项
)
```

**挂载位置**:
```
用户进程
    │
    ↓ 调用 execve()
┌─────────────────┐
│  系统调用入口    │
│  (arch/x86/...) │
└────────┬────────┘
         │
         ↓ 触发 tracepoint
┌─────────────────┐
│  tracepoint     │ ←── eBPF 程序挂载在这里
│  sys_enter_     │      tracepoint_execve()
│  execve         │
└────────┬────────┘
         │
         ↓ 执行内核处理
    实际执行程序
```

**Tracepoint 特点**:
- 内核预定义的跟踪点
- ABI 稳定，不同内核版本兼容
- 性能开销极低
- 适合系统调用跟踪

#### 3. 网络监控挂载

**挂载点**: `tc` (Traffic Control)

**类型**: TC BPF

**代码**:
```c
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    // 处理逻辑
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    // 处理逻辑
}
```

**Go 挂载代码**:
```go
// 入站挂载
ingressLink, err := link.AttachTCX(link.TCXOptions{
    Interface: ifaceIdx,           // 网卡索引
    Program:   objs.TcIngress,     // eBPF 程序
    Attach:    ebpf.AttachTCXIngress,
})

// 出站挂载
egressLink, err := link.AttachTCX(link.TCXOptions{
    Interface: ifaceIdx,
    Program:   objs.TcEgress,
    Attach:    ebpf.AttachTCXEgress,
})
```

**挂载位置**:
```
网络数据包流程:

入站 (Ingress):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    物理网卡
        │
        ↓ 接收数据包
    网卡驱动
        │
        ↓ 创建 sk_buff
┌─────────────────┐
│   TC Ingress    │ ←── eBPF 程序挂载在这里
│   (sch_handle_  │      tc_ingress()
│    ingress)     │
└────────┬────────┘
         │
         ↓ 通过/丢弃/修改
    网络协议栈
         │
    用户态 socket


出站 (Egress):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    用户态 socket
         │
         ↓ 发送数据
    网络协议栈
         │
┌─────────────────┐
│   TC Egress     │ ←── eBPF 程序挂载在这里
│   (dev_queue_   │      tc_egress()
│   _xmit)        │
└────────┬────────┘
         │
         ↓ 通过/丢弃/修改
    网卡驱动
         │
    物理网卡
```

**TC 挂载特点**:
- 在网络协议栈的入口/出口
- 可以查看和修改数据包
- 支持所有网络接口
- 性能开销低

#### 4. 挂载流程详解

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         eBPF 程序挂载流程                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 编译阶段                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  C 代码 → clang → BPF 字节码 → *.o 文件                          │   │
│  │                                                                  │   │
│  │  $ clang -O2 -target bpf -c prog.c -o prog.o                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  2. 加载阶段                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Go 程序调用 ebpf.LoadCollectionSpec()                          │   │
│  │                                                                  │   │
│  │  • 读取 ELF 文件                                                 │   │
│  │  • 验证字节码 (Verifier)                                         │   │
│  │  • JIT 编译为机器码                                              │   │
│  │  • 创建 BPF Maps                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  3. 挂载阶段                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  调用 link.Attach*() 函数                                        │   │
│  │                                                                  │   │
│  │  • 注册 eBPF 程序到内核钩子                                      │   │
│  │  • 创建 link 对象                                                │   │
│  │  • 程序开始执行                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  4. 运行阶段                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  触发条件满足时，eBPF 程序执行                                   │   │
│  │                                                                  │   │
│  │  • tracepoint: 系统调用发生时                                   │   │
│  │  • tc: 数据包经过网卡时                                         │   │
│  │  • 程序读取/写入 BPF Maps                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  5. 卸载阶段                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  调用 link.Close() 或程序退出                                   │   │
│  │                                                                  │   │
│  │  • 从内核钩子移除程序                                            │   │
│  │  • 释放 BPF Maps                                                 │   │
│  │  • 清理资源                                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 5. 查看已挂载的 eBPF 程序

```bash
# 列出所有 eBPF 程序
sudo bpftool prog list

# 示例输出
# 1234: tracepoint  name tracepoint_execve  tag abcd1234  gpl
#         loaded_at 2024-01-01T00:00:00+0000  uid 0
#         xlated 1024B  jited 2048B  memlock 4096B
#         pids ebpf-sentinel(12345)

# 查看特定程序详情
sudo bpftool prog show id 1234

# 列出所有挂载的链接
sudo bpftool link list

# 查看 tracepoint 状态
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable

# 查看 TC 挂载
tc filter show dev eth0 ingress
tc filter show dev eth0 egress
```

#### 6. 挂载点选择指南

| 监控目标 | 推荐挂载点 | 原因 |
|---------|-----------|------|
| 系统调用 | Tracepoint | 稳定、低开销 |
| 内核函数 | Kprobe | 灵活、可监控内部函数 |
| 网络包 | TC/XDP | 完整的数据包访问 |
| 用户态应用 | Uprobe | 应用级监控 |
| 调度事件 | Tracepoint/sched | 进程调度跟踪 |

---

## Q7: 如何实现数据持久化?

### 答案

eBPF-Sentinel 使用 SQLite 数据库实现数据持久化。

#### 1. 持久化架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         数据持久化架构                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │   eBPF 事件源    │                                                   │
│  │  • 进程事件      │                                                   │
│  │  • 网络事件      │                                                   │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ↓ Ring Buffer                                                 │
│  ┌─────────────────┐                                                    │
│  │   Go 事件处理器  │                                                   │
│  │  • 解析事件      │                                                   │
│  │  • 策略过滤      │                                                   │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ↓ GORM ORM                                                    │
│  ┌─────────────────┐     ┌─────────────────┐                           │
│  │   SQLite 数据库  │────→│   sentinel.db   │  ←── 持久化文件          │
│  │  • 进程事件表    │     │                 │                           │
│  │  • 网络事件表    │     │  本地文件存储    │                           │
│  └─────────────────┘     └─────────────────┘                           │
│           ↑                                                             │
│           │ SQL 查询                                                     │
│  ┌────────┴────────┐                                                    │
│  │   HTTP API      │                                                    │
│  │  • 历史查询      │                                                    │
│  │  • 数据分析      │                                                    │
│  └─────────────────┘                                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 2. 数据库设计

**进程事件表 (execve_events)**:
```go
type ExecveEvent struct {
    ID          uint64    `gorm:"primaryKey"`  // 自增主键
    PID         uint32    `json:"pid"`         // 进程ID
    PPID        uint32    `json:"ppid"`        // 父进程ID
    Comm        string    `json:"comm"`        // 进程名
    Argv0       string    `json:"argv0"`       // 命令参数
    Whitelisted bool      `json:"whitelisted"` // 是否命中白名单
    CreatedAt   time.Time `json:"created_at"`  // 创建时间
}
```

**网络事件表 (network_events)**:
```go
type NetworkEvent struct {
    ID         uint64    `gorm:"primaryKey"`
    PID        uint32    `json:"pid"`
    SrcIP      string    `json:"src_ip"`      // 源IP
    DstIP      string    `json:"dst_ip"`      // 目的IP
    SrcPort    uint16    `json:"src_port"`    // 源端口
    DstPort    uint16    `json:"dst_port"`    // 目的端口
    Protocol   uint8     `json:"protocol"`    // 协议号
    Direction  uint8     `json:"direction"`   // 方向
    PacketSize uint32    `json:"packet_size"` // 包大小
    Comm       string    `json:"comm"`        // 进程名
    CreatedAt  time.Time `json:"created_at"`
}
```

**告警事件表 (alert_events)**:
```go
type AlertEvent struct {
    ID         uint64    `gorm:"primaryKey"`
    RuleID     string    `json:"rule_id"`      // 规则ID
    Severity   string    `json:"severity"`     // 严重级别
    SourceType string    `json:"source_type"`  // 来源事件类型
    Message    string    `json:"message"`      // 告警消息
    Details    string    `json:"details"`      // JSON详情
    Status     string    `json:"status"`       // 状态 (active/resolved/terminated)
    CreatedAt  time.Time `json:"created_at"`
}
```

**用户配置表 (user_configs)**:
```go
type UserConfig struct {
    Key       string    `gorm:"primaryKey;size:128"` // 配置键
    Value     string    `gorm:"type:text"`            // 配置值
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

**白名单规则表 (whitelist_rules)**:
```go
type WhitelistRule struct {
    ID        uint64    `gorm:"primaryKey"`
    RuleType  string    `gorm:"column:type;size:32;uniqueIndex:idx_whitelist_type_value"`
    Value     string    `gorm:"size:512;uniqueIndex:idx_whitelist_type_value"`
    Enabled   bool      `gorm:"default:true"`
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

#### 3. 数据库初始化

```go
func InitDB() (*gorm.DB, error) {
    // 打开 SQLite 数据库文件
    db, err := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
    if err != nil {
        return nil, err
    }

    // 自动迁移表结构
    // 如果表不存在则创建，如果字段有变化则更新
    // 当前管理 5 张表
    err = db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{}, &AlertEvent{}, &UserConfig{}, &WhitelistRule{})
    if err != nil {
        return nil, err
    }

    DB = db
    return db, nil
}
```

#### 4. 数据写入流程

```go
// 主程序中的事件处理
for {
    record, _ := execveRd.Read()
    
    // 解析事件
    var event execveEvent
    copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)
    
    // 创建数据库记录
    dbEvent := &models.ExecveEvent{
        PID:   event.PID,
        PPID:  event.PPID,
        Comm:  comm,
        Argv0: argv0,
    }
    
    // 异步写入数据库
    if err := models.CreateEvent(dbEvent); err != nil {
        log.Printf("[execve] failed to save event: %v", err)
    }
}
```

**写入函数**:
```go
func CreateEvent(event *ExecveEvent) error {
    return DB.Create(event).Error
}
```

#### 5. 数据查询

**查询最近事件**:
```go
func GetRecentEvents(limit int) ([]ExecveEvent, error) {
    var events []ExecveEvent
    result := DB.Order("created_at desc").Limit(limit).Find(&events)
    return events, result.Error
}
```

**HTTP API 接口**:
```go
r.GET("/api/events", func(c *gin.Context) {
    events, err := models.GetRecentEvents(100)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, events)
})
```

#### 6. 数据流时序

```
时间 →

事件存储:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

eBPF程序            Go程序              GORM                SQLite
    │                  │                  │                    │
    │  Ring Buffer     │                  │                    │
    │─────────────────→│                  │                    │
    │                  │                  │                    │
    │                  │ 创建模型对象      │                    │
    │                  │ ExecveEvent{}    │                    │
    │                  │                  │                    │
    │                  │ 调用 Create()    │                    │
    │                  │─────────────────→│                    │
    │                  │                  │                    │
    │                  │                  │ 生成 SQL INSERT    │
    │                  │                  │───────────────────→│
    │                  │                  │                    │
    │                  │                  │                    │ 写入磁盘
    │                  │                  │                    │ sentinel.db
    │                  │                  │←───────────────────│
    │                  │                  │ 返回结果           │
    │                  │←─────────────────│                    │
    │                  │ 返回 error       │                    │


事件查询:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

浏览器            HTTP API            GORM                SQLite
    │                  │                  │                    │
    │ GET /api/events  │                  │                    │
    │─────────────────→│                  │                    │
    │                  │                  │                    │
    │                  │ 调用 GetRecent() │                    │
    │                  │─────────────────→│                    │
    │                  │                  │                    │
    │                  │                  │ 生成 SQL SELECT    │
    │                  │                  │───────────────────→│
    │                  │                  │                    │
    │                  │                  │                    │ 读取磁盘
    │                  │                  │←───────────────────│
    │                  │                  │ 返回记录集         │
    │                  │←─────────────────│                    │
    │                  │ 返回 []Event     │                    │
    │                  │                  │                    │
    │←─────────────────│ JSON 响应        │                    │
    │ 显示事件列表      │                  │                    │
```

#### 7. 持久化策略

**实时写入**:
- 每个事件立即写入数据库
- 保证数据不丢失
- 适合事件量不大的场景

**批量写入**（可扩展）:
```go
// 批量插入示例
var events []ExecveEvent
// 收集一批事件...
db.CreateInBatches(events, 100)
```

**数据保留策略**（可扩展）:
```go
// 删除 7 天前的数据
func CleanupOldEvents() {
    cutoff := time.Now().AddDate(0, 0, -7)
    DB.Where("created_at < ?", cutoff).Delete(&ExecveEvent{})
}
```

#### 8. 数据库文件

**位置**: 项目根目录 `sentinel.db`

**查看数据**:
```bash
# 使用 sqlite3 命令行
sqlite3 sentinel.db

# 查看表结构
.schema

# 查询进程事件
SELECT * FROM execve_events ORDER BY created_at DESC LIMIT 10;

# 查询网络事件
SELECT * FROM network_events ORDER BY created_at DESC LIMIT 10;

# 统计事件数量
SELECT COUNT(*) FROM execve_events;

# 退出
.quit
```

#### 9. 备份和恢复

```bash
# 备份
cp sentinel.db sentinel.db.backup.$(date +%Y%m%d)

# 恢复
cp sentinel.db.backup.20240101 sentinel.db
```

#### 10. 性能考虑

| 方面 | 现状 | 优化方向 |
|------|------|---------|
| 写入 | 同步写入 | 可改为批量异步 |
| 查询 | 全表扫描 | 可添加索引 |
| 存储 | 无限增长 | 可添加清理策略 |
| 并发 | SQLite 单文件 | 大数据量可换 PostgreSQL |

SQLite 适合中小规模部署，生产环境大数据量可考虑：
- PostgreSQL
- MySQL
- TimescaleDB (时序数据)
- ClickHouse (分析型)

---

## Q8: 告警系统如何工作?

### 答案

告警系统基于 EventObserver 模式，AlertPlugin 观察所有插件事件，根据可配置的规则生成告警。

#### 1. 架构

```
插件事件流 → Event Channel → dispatchPluginEvents()
                                   ↓
                              Observer 链 (AlertPlugin.HandleEvent)
                                   ↓
                            滑动窗口 (slidingWindow)
                                   ↓
                         ┌────────┴────────┐
                         ↓                  ↓
                   关联规则匹配         单指标规则检查
                   (correlation.go)    (alert_plugin.go)
                         ↓                  ↓
                         └────────┬────────┘
                                  ↓
                            冷却检查 (cooldown)
                                  ↓
                            告警事件生成 → DB + WebSocket
```

#### 2. 告警类型

**单指标告警** (每个事件独立判断):

| 规则 ID | 触发条件 | 默认阈值 | 严重级别 |
|---------|---------|---------|---------|
| `high_cpu_usage` | CPU ≥ 阈值 | 85% | warning |
| `high_memory_usage` | 内存 ≥ 阈值 | 90% | warning |
| `high_download_speed` | 下载速度 ≥ 阈值 | 10240 KB/s | warning |
| `high_upload_speed` | 上传速度 ≥ 阈值 | 10240 KB/s | warning |
| `sensitive_command_exec` | 执行 nc/ncat/nmap/tcpdump 等 | - | medium |
| `suspicious_network_port` | 连接 22/23/3389/4444/31337 | - | medium |
| `large_network_packet` | 数据包 ≥ 阈值 | 1 MB | info |

**关联规则告警** (多事件时间窗口关联):

| 规则 ID | 检测逻辑 | 严重级别 |
|---------|---------|---------|
| `reverse_shell_detected` | 敏感命令 + 可疑端口 + 时间窗口内 | critical |
| `data_exfil_detected` | 敏感路径读取 + 出站流量 | critical |
| `process_chain_attack` | 父子进程链匹配攻击模式 (bash→python→sh 等) | critical |

#### 3. 关联规则详解

**反弹 Shell 检测 (reverseShellRule)**:
- 触发条件：execve 事件（敏感命令如 nc/ncat/socat）+ network 事件（可疑端口如 4444/5555/31337）
- 时间窗口：默认 30 秒
- 识别的敏感命令：nc, ncat, netcat, socat, tcpdump, nmap, masscan, chmod, chattr

**数据外泄检测 (dataExfilRule)**:
- 触发条件：execve 事件（路径含 /etc/shadow, /etc/passwd 等敏感文件）+ 出站网络包 ≥ 阈值（默认 1MB）
- 时间窗口：默认 30 秒
- 敏感路径：/etc/shadow, /etc/passwd, /root/.ssh, /etc/ssl/private, ~/.aws/credentials

**进程链攻击检测 (processChainRule)**:
- 触发条件：父子进程链匹配已知攻击模式
- 预定义模式：bash→python→sh, bash→python3→sh, java→bash→curl, php→sh→wget

#### 4. 冷却机制

- 每个告警独立冷却（按 rule_id + 关键标识 + PID 组合键）
- 默认冷却时间：30 秒
- 冷却期间相同规则/相同进程的重复告警被抑制
- 可通过 `/api/alert/config` API 调整冷却时间

#### 5. 告警状态生命周期

```
active → resolved/terminated/exited/failed/ignored
```

- 新告警默认状态为 `active`
- 用户可通过 `PATCH /api/alerts/:id/status` 更新状态
- 前端仅对 `active` 状态 + 含 PID 的告警显示"终止进程"按钮

#### 6. 配置 API

```
GET  /api/alert/config    → 获取当前配置
POST /api/alert/config    → 更新配置（需要 Admin Token）
```

配置项 (AlertConfig):
```json
{
  "cpu_threshold": 85.0,
  "memory_threshold": 90.0,
  "net_speed_threshold_kb": 10240.0,
  "packet_size_limit": 1048576,
  "cooldown_seconds": 30,
  "correlation_window_seconds": 60,
  "max_time_gap_seconds": 60,
  "exfil_size_threshold_bytes": 1048576,
  "single_metric_alerts_enabled": false
}
```

---

## Q9: 白名单系统如何工作?

### 答案

白名单系统通过 REST API 管理，持久化到 SQLite，并同步到 eBPF Maps 和内存策略。

#### 1. 三种白名单类型

| 类型 | 存储位置 | 生效方式 | 用途 |
|------|---------|---------|------|
| IP 白名单 | eBPF Hash Map (ip_whitelist) | 内核空间过滤 | 信任特定 IP 的流量 |
| 端口白名单 | eBPF Hash Map (port_whitelist) | 内核空间过滤 | 信任特定端口的流量 |
| 可执行路径白名单 | 内存策略 (execPathWhitelistPolicy) | 用户态抑制告警推导 | 信任特定进程的执行 |

#### 2. 路径匹配模式

可执行路径白名单支持四种匹配模式：

| 模式 | 示例 | 匹配 |
|------|------|------|
| 精确匹配 | `/usr/bin/chmod` | `/usr/bin/chmod` |
| 基础名匹配 | `chmod` | `/usr/bin/chmod`, `/bin/chmod` |
| 目录前缀 | `/usr/local/bin/` | `/usr/local/bin/tool` |
| 通配符 | `/opt/trusted/*` | `/opt/trusted/agent` |

#### 3. 同步机制

- IP/端口白名单：创建/更新/删除规则后，立即同步到 eBPF Hash Maps（内核空间生效）
- 可执行路径白名单：创建/更新/删除规则后，重新加载内存策略
- 同步失败时自动回滚 DB 操作（consistent 模式）

#### 4. REST API

```
GET    /api/whitelist?type=ip&enabled_only=true    → 查询
POST   /api/whitelist                              → 创建
PATCH  /api/whitelist/:id                          → 更新
DELETE /api/whitelist/:id                          → 删除
```

---

## Q10: 安全访问控制如何工作?

### 答案

安全中间件 (`requireMutationAccess()`) 保护所有变更操作端点。

#### 1. 访问控制策略

```
请求 → requireMutationAccess() 中间件
         ↓
    ┌────────────────────┐
    │ 来自 localhost?    │──是──→ 放行
    └────────────────────┘
         │否
         ↓
    ┌────────────────────┐
    │ 携带有效 Token?    │──是──→ 放行
    └────────────────────┘
         │否
         ↓
    403 Forbidden
```

#### 2. Token 配置

```bash
# 启动时设置 Admin Token
export SENTINEL_ADMIN_TOKEN="your-secret-token-here"
sudo -E ./eBPF-Sentinel

# 未设置 Token → 仅 localhost 可变更
# 设置了 Token → localhost 免 Token，远程需携带 Token
```

#### 3. Token 携带方式

```
# 方式一：Authorization Bearer
curl -H "Authorization: Bearer $SENTINEL_ADMIN_TOKEN" \
     -X POST http://host:8080/api/policy/execve/true

# 方式二：X-Sentinel-Token
curl -H "X-Sentinel-Token: $SENTINEL_ADMIN_TOKEN" \
     -X POST http://host:8080/api/policy/execve/true
```

#### 4. 安全特性

- Token 比较使用 `crypto/subtle.ConstantTimeCompare`（防止时序攻击）
- Token 长度必须完全匹配
- 仅读接口（GET）始终无需认证

---

## Q11: 插件架构如何设计?

### 答案

插件系统采用接口驱动设计，通过 Manager 统一管理所有插件的生命周期。

#### 1. 核心接口

```go
// Plugin 接口：每个监控插件必须实现
type Plugin interface {
    Name() string
    Description() string
    Load() error                              // 加载 eBPF 对象
    Attach() error                            // 挂载到内核
    Detach() error                            // 卸载
    Close() error                             // 清理资源
    Start(eventChan chan<- *Event) error      // 开始采集（阻塞，在 goroutine 中运行）
}

// EventObserver 接口：观察事件生成衍生事件的插件
type EventObserver interface {
    HandleEvent(event *Event) []*Event        // 返回 nil 或多个衍生事件
}

// PolicyControl 接口：插件启用/禁用控制
type PolicyControl interface {
    IsEnabled() bool
    SetEnabled(bool) error
}
```

#### 2. 插件生命周期

```
Register() → LoadAll() → AttachAll() → StartAll(goroutines) → [运行] → DetachAll() → CloseAll()
```

每个插件在 `StartAll()` 时获得独立 goroutine，通过共享 event channel 发送事件。

#### 3. 事件分发流程

```
┌─────────────┐
│ ExecvePlugin │──┐
└─────────────┘  │
┌─────────────┐  │    ┌──────────────────────┐    ┌──────────────┐
│NetworkPlugin│──┼───→│   Event Channel      │───→│dispatchPlugin│
└─────────────┘  │    │  (chan *Event, 256)  │    │    Events()  │
┌─────────────┐  │    └──────────────────────┘    └──────┬───────┘
│  CPUPlugin  │──┤                                        │
└─────────────┘  │                     ┌──────────────────┼──────────────────┐
┌─────────────┐  │                     ↓                  ↓                  ↓
│SystemMonitor│──┘              persistEvent()   broadcastPluginEvent()  manager.Observers()
└─────────────┘                      ↓                  ↓                  ↓
                                  SQLite            WebSocket          AlertPlugin
                                                                     (HandleEvent)
```

#### 4. 已注册的 5 个插件

| 插件 | 数据源 | 事件类型 | 特殊接口 |
|------|--------|---------|---------|
| ExecvePlugin | eBPF sys_enter_execve | execve | PolicyControl |
| NetworkPlugin | eBPF TC ingress/egress | network | PolicyControl + Whitelist |
| CPUPlugin | eBPF sched_switch | (内部使用) | GetCPUUsage() |
| SystemMonitorPlugin | eBPF CPU + gopsutil | system | (无) |
| AlertPlugin | EventObserver 链 | alert | EventObserver |

#### 5. 设计优势

- **关注点分离**: 每个插件独立管理其 eBPF 程序和生命周期
- **可扩展**: 添加新监控类型只需实现 Plugin 接口
- **统一事件总线**: 所有事件通过单一 channel 流转，便于统一处理
- **观察者模式**: EventObserver 接口允许插件推导衍生事件，无需修改原有插件
