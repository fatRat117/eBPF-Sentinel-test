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

| 接口 | 方法 | 功能 |
|------|------|------|
| `/api/events` | GET | 获取进程事件 |
| `/api/network-events` | GET | 获取网络事件 |
| `/api/processes` | GET | 获取进程列表（带缓存） |
| `/api/policy/status` | GET | 获取监控状态 |
| `/api/process/kill/:pid` | POST | 终止进程 |
| `/ws` | WebSocket | 实时事件流 |

#### 6. 插件系统

**插件接口**:
```go
type Plugin interface {
    Name() string
    Load() error
    Attach() error
    Start(eventChan chan<- *Event) error
}
```

**系统监控插件**:
- 采集 CPU 使用率
- 采集网络速度
- 不依赖 eBPF

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
- CPU 使用率（百分比）
- 网络入站速度（KB/s）
- 网络出站速度（KB/s）

**说明**: CPU使用率通过eBPF tracepoint sched_switch采集，网络速度通过gopsutil库采集。
**监控方式**: eBPF tracepoint sched_switch (CPU) 和 gopsutil 库（网络速度）

**用途**:
- 系统负载监控
- 资源使用趋势
- 性能瓶颈分析

**示例事件**:
```json
{
  "type": "system",
  "data": {
    "cpu_usage": "23.5",
    "net_speed_in": "150.2",
    "net_speed_out": "45.8"
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
| 系统指标 | eBPF (CPU) + gopsutil (网络) | 1秒间隔 | 极低 |

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
    ID        uint64    `gorm:"primaryKey"`  // 自增主键
    PID       uint32    `json:"pid"`         // 进程ID
    PPID      uint32    `json:"ppid"`        // 父进程ID
    Comm      string    `json:"comm"`        // 进程名
    Argv0     string    `json:"argv0"`       // 命令参数
    CreatedAt time.Time `json:"created_at"`  // 创建时间
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
    err = db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{})
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
