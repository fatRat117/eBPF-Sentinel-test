# eBPF 最小模型教程

本教程以教学为目的，从零开始构建一个最小的 eBPF 监控系统。我们将逐步实现:

1. 最简单的 eBPF 程序（Hello World）
2. 带参数传递的 eBPF 程序
3. 使用 Ring Buffer 的完整示例
4. 集成到 Go 程序的完整流程

---

## 第一部分：eBPF Hello World

### 目标
编写一个最简单的 eBPF 程序，在每次 execve 系统调用时输出日志。

### 代码

创建 `minimal_hello.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// SEC 宏定义程序的挂载点
// tp/syscalls/sys_enter_execve 表示 syscalls 子系统的 sys_enter_execve tracepoint
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // bpf_printk 是 eBPF 的调试输出函数
    // 输出可以在 /sys/kernel/debug/tracing/trace_pipe 查看
    bpf_printk("Hello eBPF! execve called\\n");
    return 0;
}

// 许可证声明，GPL 允许使用更多内核功能
char LICENSE[] SEC("license") = "GPL";
```

### 关键概念解释

#### 1. SEC 宏
```c
SEC("tp/syscalls/sys_enter_execve")
```
- `SEC` 是 section 的缩写，用于指定程序的挂载点
- `tp/syscalls/sys_enter_execve` 表示 tracepoint
- 其他常见挂载点:
  - `kprobe/<function>`: 内核函数入口
  - `kretprobe/<function>`: 内核函数返回
  - `tc`: Traffic Control (网络)
  - `xdp`: 网络包处理

#### 2. bpf_printk
```c
bpf_printk("Hello eBPF!\\n");
```
- 类似于 C 语言的 printf
- 输出到内核跟踪管道
- 查看方式: `sudo cat /sys/kernel/debug/tracing/trace_pipe`
- **注意**: 有性能开销，仅用于调试

#### 3. 许可证
```c
char LICENSE[] SEC("license") = "GPL";
```
- 必须声明，否则加载失败
- GPL 允许访问 GPL 许可的内核函数

### 编译和运行

```bash
# 编译 eBPF 程序
clang -O2 -g -target bpf -c minimal_hello.c -o minimal_hello.o

# 使用 bpftool 加载
sudo bpftool prog load minimal_hello.o /sys/fs/bpf/minimal_hello

# 查看输出 (在另一个终端)
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 测试：执行任意命令
ls

# 卸载
sudo rm /sys/fs/bpf/minimal_hello
```

---

## 第二部分：获取进程信息

### 目标
在 eBPF 程序中获取当前进程的 PID 和进程名。

### 代码

创建 `minimal_pid.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 获取当前进程 PID
    // bpf_get_current_pid_tgid() 返回 64 位值：高 32 位是 PID，低 32 位是 TGID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 获取进程名
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_printk("PID: %d, Comm: %s\\n", pid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 关键概念解释

#### 1. 获取 PID
```c
u32 pid = bpf_get_current_pid_tgid() >> 32;
```
- `bpf_get_current_pid_tgid()` 返回 `pid_tgid` 组合值
- 高 32 位: PID (进程 ID)
- 低 32 位: TGID (线程组 ID，对于单线程进程等于 PID)

#### 2. 获取进程名
```c
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));
```
- `bpf_get_current_comm` 获取当前任务的 `task_struct->comm`
- 最大长度 16 字节（包括结尾的 `\0`）
- 是进程的可执行文件名（不是完整路径）

### 编译和测试

```bash
# 编译
clang -O2 -g -target bpf -c minimal_pid.c -o minimal_pid.o

# 加载
sudo bpftool prog load minimal_pid.o /sys/fs/bpf/minimal_pid

# 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 测试
sleep 1 &
```

---

## 第三部分：使用 Ring Buffer 传输数据

### 目标
使用 Ring Buffer 将数据从内核态传输到用户态。

### 为什么需要 Ring Buffer？

| 方式 | 优点 | 缺点 |
|------|------|------|
| bpf_printk | 简单 | 只能调试，用户态无法读取 |
| BPF Maps | 双向通信 | 需要轮询 |
| Ring Buffer | 异步、高效、支持批量 | 只能内核→用户 |

Ring Buffer 是内核 5.8+ 推荐的事件传输机制。

### 代码

创建 `minimal_ringbuf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义事件结构体
struct event {
    u32 pid;
    char comm[16];
    char filename[128];  // 执行的文件名
};

// 定义 Ring Buffer Map
// SEC(".maps") 表示这是一个 BPF Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB 缓冲区
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 在 Ring Buffer 中预留空间
    // 参数: map, 大小, flags
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        // 缓冲区已满，丢弃事件
        return 0;
    }
    
    // 填充事件数据
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 从 tracepoint 上下文读取第一个参数（文件名）
    // ctx->args[0] 是用户空间指针
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    
    // 提交事件到 Ring Buffer
    // 用户态程序可以读取
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 关键概念解释

#### 1. BPF Map 定义
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```
- 使用匿名结构体 + `SEC(".maps")` 定义 Map
- `__uint` 是 BPF 内核中的辅助宏
- 支持的 Map 类型:
  - `BPF_MAP_TYPE_RINGBUF`: 环形缓冲区
  - `BPF_MAP_TYPE_HASH`: 哈希表
  - `BPF_MAP_TYPE_ARRAY`: 数组
  - `BPF_MAP_TYPE_PERCPU_ARRAY`: Per-CPU 数组

#### 2. Ring Buffer 操作
```c
// 1. 预留空间
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

// 2. 填充数据
e->pid = ...;

// 3. 提交（或丢弃）
bpf_ringbuf_submit(e, 0);      // 提交
// bpf_ringbuf_discard(e, 0);  // 丢弃
```

#### 3. 读取用户空间数据
```c
bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
```
- `bpf_probe_read_user_str`: 从用户空间安全读取字符串
- `bpf_probe_read_kernel_str`: 从内核空间读取
- 必须使用这些辅助函数，直接访问会触发 verifier 错误

---

## 第四部分：Go 用户态程序

### 目标
编写 Go 程序加载 eBPF 并读取 Ring Buffer。

### 完整代码

创建 `main.go`:

```go
package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

// 定义事件结构体（必须与 C 代码完全匹配）
type Event struct {
    PID      uint32
    Comm     [16]byte
    Filename [128]byte
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang minimal minimal_ringbuf.c -- -I./headers

func main() {
    // 1. 移除内存限制（eBPF 需要锁定内存）
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("failed to remove memlock: %v", err)
    }

    // 2. 加载 eBPF 对象
    // 假设 bpf2go 生成了 minimalObjects 结构体
    objs := &minimalObjects{}
    if err := loadMinimalObjects(objs, nil); err != nil {
        log.Fatalf("failed to load objects: %v", err)
    }
    defer objs.Close()

    // 3. 挂载到 tracepoint
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
    if err != nil {
        log.Fatalf("failed to attach tracepoint: %v", err)
    }
    defer tp.Close()

    // 4. 打开 Ring Buffer 读取器
    rd, err := ringbuf.NewReader(objs.Rb)
    if err != nil {
        log.Fatalf("failed to open ring buffer: %v", err)
    }
    defer rd.Close()

    // 5. 设置信号处理（Ctrl+C 退出）
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

    // 6. 启动读取循环
    go func() {
        for {
            record, err := rd.Read()
            if err != nil {
                if err == ringbuf.ErrClosed {
                    return
                }
                log.Printf("read error: %v", err)
                continue
            }

            // 解析事件
            var event Event
            if len(record.RawSample) < int(unsafe.Sizeof(event)) {
                continue
            }

            // 使用 unsafe 快速解析二进制数据
            copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)

            // 转换为字符串
            comm := string(bytes.Trim(event.Comm[:], "\x00"))
            filename := string(bytes.Trim(event.Filename[:], "\x00"))

            fmt.Printf("PID: %d, Comm: %s, File: %s\n", event.PID, comm, filename)
        }
    }()

    <-sig
    log.Println("Exiting...")
}
```

### 关键概念解释

#### 1. 内存限制
```go
rlimit.RemoveMemlock()
```
- eBPF 程序需要锁定内存
- 默认限制可能不足
- 需要 root 权限

#### 2. bpf2go
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...
```
- Go 的代码生成工具
- 编译 C 代码为 eBPF 字节码
- 生成 Go 绑定代码

#### 3. 加载 eBPF 对象
```go
objs := &minimalObjects{}
loadMinimalObjects(objs, nil)
```
- `minimalObjects` 由 bpf2go 生成
- 包含程序和 Map 的引用
- 自动验证和加载

#### 4. 挂载程序
```go
link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
```
- 将 eBPF 程序挂载到内核钩子
- 支持多种挂载类型:
  - `link.Tracepoint`: 跟踪点
  - `link.Kprobe`: 内核函数入口
  - `link.AttachTCX`: TC 挂载

#### 5. 读取 Ring Buffer
```go
rd, _ := ringbuf.NewReader(objs.Rb)
record, _ := rd.Read()
```
- 阻塞读取
- 返回原始字节
- 需要手动解析

#### 6. 数据解析
```go
copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)
```
- 使用 `unsafe` 包高效解析
- 必须确保大小匹配
- 注意字节序和对齐

---

## 第五部分：运行完整示例

### 目录结构
```
minimal-ebpf/
├── minimal_ringbuf.c    # eBPF C 代码
├── main.go              # Go 程序
├── go.mod               # Go 模块
└── headers/             # 头文件目录
    └── vmlinux.h        # 内核头文件
```

### 步骤

1. **初始化 Go 模块**
```bash
go mod init minimal-ebpf
go get github.com/cilium/ebpf
```

2. **生成 vmlinux.h**（如果还没有）
```bash
# 需要 bpftool
bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
```

3. **生成 Go 绑定**
```bash
go generate
```

4. **运行程序**
```bash
sudo go run .
```

5. **测试**
在另一个终端执行命令，观察输出。

---

## 总结

通过这个最小模型，我们学习了：

1. **eBPF 程序基础**: SEC 宏、bpf_printk、许可证
2. **获取内核数据**: PID、进程名、系统调用参数
3. **数据传输**: Ring Buffer 的使用
4. **Go 集成**: 加载、挂载、读取

### 下一步

- 学习网络监控（TC/XDP）
- 了解更多的 Map 类型
- 探索 kprobe 和 uprobe
- 学习 eBPF 验证器规则

> **提示**: 本教程展示的是 eBPF 最基础的工作原理。实际的 eBPF-Sentinel 项目使用了更高级的插件架构（Plugin 接口、EventObserver 模式、Manager 生命周期管理），支持 5 个插件并行运行。如果你想了解完整的项目构建过程，请参考 [doc/tutorial.md](../tutorial.md)。
