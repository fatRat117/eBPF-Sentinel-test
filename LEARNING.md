# eBPF-Sentinel 学习指南

## 项目概述

eBPF-Sentinel 是一个基于 eBPF (Extended Berkeley Packet Filter) 技术的实时系统监控与治理平台。它能够监控系统调用、网络流量、CPU 使用率和网络速度，并提供进程管理能力。

## 项目架构

```text
┌─────────────────────────────────────────────────────────────────┐
│                         用户态 (User Space)                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Gin Web   │  │  WebSocket  │  │   SQLite    │             │
│  │   Server    │  │    Hub      │  │  Database   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                 │                 │                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    main.go (入口)                            ││
│  │  - 加载 eBPF 程序                                            ││
│  │  - 挂载到内核钩子                                            ││
│  │  - 读取 Ring Buffer 事件                                     ││
│  │  - 插件管理器                                                ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                      插件层 (Plugin Layer)                       │
│  ┌──────────────────┐  ┌──────────────────┐                     │
│  │  Execve Plugin  │  │ System Monitor  │                     │
│  │  (进程监控)      │  │  Plugin (系统)   │                     │
│  └──────────────────┘  └──────────────────┘                     │
├─────────────────────────────────────────────────────────────────┤
│                    Go ↔ eBPF 桥梁 (cilium/ebpf)                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │     bpf2go 自动生成 Go 绑定代码 (*_bpfel.go)                 ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      内核态 (Kernel Space)                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────────────────────┐│
│  │ execve.c           │  │ network.c                          ││
│  │ sys_enter_execve  │  │  tc_ingress / tc_egress            ││
│  │ tracepoint        │  │  (Traffic Control)                 ││
│  └─────────────────────┘  └─────────────────────────────────────┘│
│         ↓                          ↓                            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    BPF Maps                                 ││
│  │  - Ring Buffer (事件传输)                                   ││
│  │  - Hash Map (白名单)                                        ││
│  │  - Array Map (开关状态)                                     ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## 核心组件详解

### 1. eBPF 程序层 (`ebpf/`)

#### execve.c - 进程监控

```c
SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
```

- **钩子点**: Tracepoint `syscalls:sys_enter_execve`
- **功能**: 捕获所有 execve 系统调用
- **关键点**: 使用 `bpf_ringbuf_reserve/submit` 异步发送事件

#### network.c - 网络监控

```c
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
```

- **钩子点**: TC (Traffic Control) ingress/egress
- **功能**: 捕获所有经过网卡的数据包
- **关键点**: 解析以太网头、IP头、TCP/UDP头

### 2. Go 绑定层

#### `*_bpfel.go` 文件

- 由 `go generate` + `bpf2go` 自动生成
- 包含 eBPF 程序和 Map 的 Go 结构体定义
- **关键文件**:
  - `execve_x86_bpfel.go`
  - `network_bpfel_x86.go`

### 3. 主程序 (`main.go`)

核心流程：

```text
1. 初始化数据库 (SQLite)
2. 创建 WebSocket Hub
3. 移除内存限制 (rlimit.RemoveMemlock)
4. 加载 eBPF 对象 (load*Objects)
5. 挂载到内核 (link.Tracepoint / link.AttachTCX)
6. 打开 Ring Buffer 读取器
7. 启动事件处理 goroutine
8. 启动插件 (System Monitor)
9. 启动 Web 服务器
```

### 4. 插件系统 (`internal/plugin/`)

#### plugin.go - 插件接口定义

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

#### system_plugin.go - 系统监控插件

- 使用 `gopsutil` 库采集系统指标
- CPU 使用率: `cpu.Percent()`
- 网速计算: 差分计算 `net.IOCounters`

### 5. Web 层

#### websocket/hub.go

- 管理 WebSocket 连接
- 广播消息给所有客户端

#### models/event.go

- GORM 模型定义
- 数据库操作封装

## 学习路径推荐

### 阶段 1: 基础概念 (1-2天)

1. **eBPF 入门**
   - [eBPF 官方文档](https://ebpf.io/)
   - [什么是 eBPF?](https://ebpf.io/what-is-ebpf/)

2. **Tracepoint 基础**

   ```bash
   # 查看可用的 tracepoint
   sudo ls /sys/kernel/debug/tracing/events/syscalls/

   # 查看特定 tracepoint 的格式
   sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
   ```

3. **TC (Traffic Control) 基础**

   ```bash
   # 查看网络接口
   ip link show

   # 查看 tc 类
   tc qdisc show
   ```

### 阶段 2: 核心代码阅读 (2-3天)

1. **从 eBPF C 代码开始**
   - `ebpf/execve.c` - 最简单的 tracepoint 示例
   - `ebpf/network.c` - 较复杂的包处理示例

2. **理解 bpf2go 工作流程**

   ```bash
   # 查看生成命令
   head -5 main.go | grep go:generate

   # 手动触发生成
   go generate
   ```

3. **阅读 Go 端加载代码**
   - `main.go` 中的 `loadExecveObjects` 调用
   - 理解 `ebpf.CollectionSpec.LoadAndAssign`

### 阶段 3: 插件系统 (1-2天)

1. **理解插件接口**
   - 阅读 `internal/plugin/plugin.go`

2. **实现自己的插件**
   - 参考 `internal/plugin/execve_plugin.go`
   - 参考 `internal/plugin/system_plugin.go`

### 阶段 4: Web 层 (1-2天)

1. **Gin 路由**
   - 阅读 `main.go` 中的 `setupRoutes` 函数

2. **WebSocket 实时推送**
   - 阅读 `internal/websocket/hub.go`
   - 理解广播机制

3. **前端交互**
   - 阅读 `web/dist/index.html`
   - 理解事件处理流程

## 关键技术点

### 1. Ring Buffer 高效事件传递

```c
// 内核态: 预留并提交事件
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (e) {
    // 填充数据
    bpf_ringbuf_submit(e, 0);
}
```

```go
// 用户态: 读取事件
reader, _ := ringbuf.NewReader(obj.Events)
for {
    record, _ := reader.Read()
    // 处理 record.RawSample
}
```

**巧妙之处**: 内核到用户态的零拷贝异步通信

### 2. 包解析 (network.c)

```c
// 边界检查防止越界
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return 0;

// 解析IP头
struct iphdr *ip = data + ETH_HLEN;
u8 protocol = ip->protocol;

// 解析TCP/UDP端口
struct tcphdr *tcp = ip_data + ip_header_len;
u16 src_port = bpf_ntohs(tcp->source);
```

**关键**: 所有的指针访问都必须先进行边界检查

### 3. 采样机制 (network.c)

```c
// 简单计数器采样
u64 new_val = *counter + 1;
bpf_map_update_elem(&sample_counter, &key, &new_val, BPF_ANY);
return (new_val % SAMPLE_RATE) == 0;
```

**作用**: 在高流量场景下减少事件数量，降低性能开销

### 4. Go 与 eBPF 的桥梁

```go
// bpf2go 生成的结构体
type execveObjects struct {
    execvePrograms
    execveMaps
}

type execveMaps struct {
    Events *ebpf.Map `ebpf:"events"`
}

type execvePrograms struct {
    TracepointExecve *ebpf.Program `ebpf:"tracepoint_execve"`
}
```

**巧妙之处**: 通过 struct tag 自动关联 eBPF 对象

### 5. WebSocket 广播机制

```go
type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte      // 广播通道
    register   chan *Client
    unregister chan *Client
}

// 单生产者多消费者模式
func (h *Hub) Run() {
    for {
        select {
        case message := <-h.broadcast:
            // 发送给所有客户端
        }
    }
}
```

## 难点分析

### 1. eBPF 编译环境

- **问题**: 需要特定版本的 clang/llvm
- **解决**:

  ```bash
  # 安装依赖
  sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

  # 验证安装
  clang --version
  llc --version
  ```

### 2. 内核版本兼容性

- **问题**: 不同内核版本的 BTF 可能不同
- **解决**: 使用 `vmlinux.h` 生成器或预编译

### 3. 内存限制

- **问题**: eBPF 需要锁定内存
- **解决**:

  ```go
  if err := rlimit.RemoveMemlock(); err != nil {
      log.Fatalf("failed to remove memlock limit: %v", err)
  }
  ```

### 4. 权限要求

- **问题**: 加载 eBPF 程序需要 root 权限
- **解决**: 使用 `sudo` 运行

### 5. 数据结构对齐

- **问题**: Go 和 C 的结构体内存布局可能不同
- **解决**: 使用固定长度数组 `[16]byte` 而非 string

## 代码巧妙之处

### 1. 统一事件通道

```go
eventChan := make(chan *plugin.Event, 256)

go func() {
    for event := range eventChan {
        hub.Broadcast(map[string]interface{}{
            "type": event.Type,
            "data": event.Data,
        })
    }
}()
```

- 所有插件通过同一个通道发送事件
- 解耦了数据采集和数据分发

### 2. 插件化设计

```go
type Plugin interface {
    Load() error
    Attach() error
    Start(eventChan chan<- *Event) error
}
```

- 统一的接口定义
- 便于扩展新的监控类型

### 3. 白名单过滤 (用户态)

```go
func isInWhitelist(comm string) bool {
    return execveWhitelist[comm]
}
```

- 在用户态过滤，减少内核复杂度
- 动态可配置

### 4. 协程分离

```go
// 每个事件源独立 goroutine
go readExecveEvents()
go readNetworkEvents()
go systemPlugin.Start(eventChan)
```

- 不会阻塞主线程
- 独立错误处理

## 调试技巧

### 1. 查看 eBPF 程序状态

```bash
# 列出所有加载的 eBPF 程序
bpftool prog list

# 查看特定程序的详细信息
sudo bpftool prog show id <id>

# 查看 eBPF Map
bpftool map list
```

### 2. Tracepoint 调试

```bash
# 启用 tracepoint 跟踪
sudo echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable

# 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 3. 添加日志

```c
// 在 eBPF 中使用 bpf_printk (查看方式同上)
bpf_printk("PID: %d\n", e->pid);
```

### 4. Go 端调试

```go
// 启用 eBPF 日志
spec, err := loadExecve()
if err != nil {
    log.Printf("Spec: %+v", spec)
}
```

## 扩展建议

### 1. 添加新的 eBPF 监控

- 在 `ebpf/` 目录创建新的 C 文件
- 添加 `go:generate` 指令
- 在 main.go 中加载和挂载

### 2. 添加新的插件

- 实现 `Plugin` 接口
- 在 main.go 中初始化并启动

### 3. 添加新的 API

- 在 `setupRoutes` 中添加路由
- 使用 GORM 进行数据库操作

### 4. 前端扩展

- 添加新的标签页
- 使用 WebSocket 接收实时数据

## 推荐学习资源

### 官方文档

1. [eBPF.io](https://ebpf.io/) - 官方入口
2. [Cilium eBPF 文档](https://docs.cilium.io/en/stable/bpf/) - 最详细的 eBPF 指南
3. [bpftrace 教程](https://github.com/iovisor/bpftrace) - 快速原型

### 在线教程

1. [eBPF for Security](https://www.elastic.co/blog/ebpfforsecurity)
2. [Learning eBPF](https://www.learningcoeBPF.com/)

### 书籍

1. "Linux Observability with eBPF" - 深入理解 eBPF
2. "Security Observability with eBPF" - 安全应用

### 实践项目

1. [bpftrace 工具](https://github.com/iovisor/bpftrace) - 各种 eBPF 工具示例
2. [falco](https://github.com/falcosecurity/falco) -容器安全监控
3. [cilium](https://github.com/cilium/cilium) - 网络与安全

## 常见问题 (FAQ)

**Q: 为什么需要 root 权限?**
A: 加载 eBPF 程序需要 CAP_SYS_ADMIN 或 root 权限

**Q: 如何选择 tracepoint vs kprobe?**
A: tracepoint 更稳定但数量有限; kprobe 灵活但可能因内核版本变化

**Q: Ring Buffer vs Perf Buffer 区别?**
A: Ring Buffer 效率更高，支持单生产者多消费者

**Q: 如何处理高流量场景?**
A: 使用采样机制，或在 eBPF 端进行数据聚合

**Q: 程序加载失败怎么办?**
A: 检查内核支持、使用 `bpftool prog load` 调试、查看 dmesg

## 快速实验

### 1. 验证环境

```bash
# 检查内核支持
uname -r
cat /proc/sys/kernel/bpf_stats_enabled

# 检查权限
id
```

### 2. 运行项目

```bash
# 编译
go build -o ebpf-sentinel .

# 运行 (需要 sudo)
sudo ./ebpf-sentinel

# 访问
# 浏览器打开 http://localhost:8080
```

### 3. 查看输出

```bash
# 终端查看日志
sudo ./ebpf-sentinel 2>&1 | grep -E "\[EXECVE\]|\[NETWORK\]|\[system\]"

# 查看 eBPF 程序
sudo bpftool prog list | grep -i sentinel
```
