# eBPF-Sentinel 从零构建教程

> 目标：从一个空文件夹开始，逐步构建一个完整的 Linux 系统监控工具。你将亲手写出每一层代码，理解它们为什么这样设计。

---

## 目录

1. [先决条件与概念准备](#1-先决条件与概念准备)
2. [最小可运行系统：第一个 eBPF 程序](#2-最小可运行系统第一个-ebpf-程序)
3. [用户态桥梁：用 Go 加载 eBPF](#3-用户态桥梁用-go-加载-ebpf)
4. [数据持久化：SQLite + GORM](#4-数据持久化sqlite--gorm)
5. [实时推送：WebSocket 广播](#5-实时推送websocket-广播)
6. [HTTP API：Gin 路由层](#6-http-apigin-路由层)
7. [可视化：单页 Dashboard](#7-可视化单页-dashboard)
8. [扩展网络监控](#8-扩展网络监控)
9. [扩展 CPU 监控](#9-扩展-cpu-监控)
10. [完整整合与运行](#10-完整整合与运行)
11. [进阶话题](#11-进阶话题)

---

## 1. 先决条件与概念准备

### 1.1 你需要什么

- **Linux 系统**（内核 5.8+，需要支持 BPF ring buffer 和 TCX）
- **Go 1.25+**
- **Clang/LLVM**（编译 eBPF C 代码，建议 clang-14 或更高）
- **root 权限**（加载 eBPF 程序需要）
- 基础了解 C 语言和 Go 语言

### 1.2 核心概念：eBPF 是什么？

**eBPF（extended Berkeley Packet Filter）** 是 Linux 内核的一项革命性技术，允许你在内核中安全地运行沙盒程序，而无需修改内核源码或加载内核模块。

想象内核是一个黑盒，以前你只能从外部观察（通过 /proc、系统调用等）。eBPF 让你可以**把代码注入内核**，在内核事件发生时执行你的逻辑。

**为什么用 eBPF 做监控？**
- **高性能**：程序运行在内核空间，无需用户态/内核态频繁切换
- **低侵入**：不需要修改被监控的程序
- **安全**：eBPF  verifier 会在加载前检查程序安全性（无死循环、无越界访问等）
- **实时**：事件发生时立即触发，无轮询延迟

### 1.3 我们的架构分层

```
┌────────────────────────────────────────────┐
│  Layer 4: Web Dashboard (HTML/CSS/JS)      │  ← 你在浏览器看到的
│  Layer 3: HTTP API + WebSocket (Gin + WS)  │  ← Go HTTP 服务器
│  Layer 2: Event Processing + Storage       │  ← Go 业务逻辑
│  Layer 1: eBPF Loader (cilium/ebpf)        │  ← Go 加载 eBPF
│  Layer 0: eBPF Programs (C)                │  ← 内核中的程序
└────────────────────────────────────────────┘
```

数据流：
```
内核事件 → eBPF C 程序 → Ring Buffer → Go 读取 → SQLite 存储 + WebSocket 广播 → 前端展示
```

---

## 2. 最小可运行系统：第一个 eBPF 程序

我们先写**最简单的 eBPF 程序**：监控 `execve` 系统调用（进程执行）。

### 2.1 创建项目目录

```bash
mkdir ~/ebpf-sentinel && cd ~/ebpf-sentinel
```

### 2.2 什么是 vmlinux.h？

eBPF 程序运行在内核空间，需要访问内核数据结构（如 `task_struct`）。传统方式需要安装内核头文件，但不同发行版的头文件路径不同。

**vmlinux.h** 是一个自包含的头文件，包含了当前内核的所有类型定义。你可以通过 `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` 生成。

但在本教程中，你可以直接使用项目提供的 `vmlinux.h`，或者从 https://github.com/libbpf/vmlinux.h 获取适合你内核版本的文件。

```bash
mkdir ebpf
```

### 2.3 编写 execve.c

创建 `ebpf/execve.c`：

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义事件结构体——这是内核和用户态共享的数据格式
struct event {
    u32 pid;                    // 进程ID
    u32 ppid;                   // 父进程ID
    char comm[16];              // 进程名（最多16字节）
    char argv0[128];            // 执行的命令
};

// Ring Buffer Map —— 内核→用户态的事件通道
// 类型：BPF_MAP_TYPE_RINGBUF（高效的无锁环形缓冲区）
// 大小：256KB
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// SEC() 宏标记这个函数应该挂载到哪里
// "tp/syscalls/sys_enter_execve" = tracepoint/syscalls/sys_enter_execve
// 意思是：每次系统调用 execve 进入时，执行这个函数
SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    const char *filename;
    
    // 1. 在 Ring Buffer 中预留空间
    // 如果缓冲区满了，返回 NULL，我们直接放弃这个事件
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // 2. 获取当前任务的 task_struct
    // bpf_get_current_task() 返回当前正在运行的进程的 task_struct 指针
    task = (struct task_struct *)bpf_get_current_task();
    
    // 3. 获取 PID
    // bpf_get_current_pid_tgid() 返回 64 位值：高 32 位是 PID，低 32 位是 TGID
    // 右移 32 位得到 PID
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    // 4. 获取父进程 PID
    // 从 task->real_parent 读取父进程指针，再读其 tgid
    // bpf_probe_read_kernel() 是安全读取内核内存的辅助函数
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
    
    // 5. 获取进程名
    // bpf_get_current_comm() 把当前进程名写入缓冲区
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 6. 读取 execve 的第一个参数（文件名）
    // ctx->args[0] 是用户空间指针，需要用 bpf_probe_read_user_str() 读取
    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->argv0, sizeof(e->argv0), filename);
    
    // 7. 提交事件到 Ring Buffer
    // 用户态程序现在可以读到这个事件
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 许可证声明 —— GPL 允许使用更多内核辅助函数
char LICENSE[] SEC("license") = "GPL";
```

### 2.4 关键概念解释

**Q: 为什么是 tracepoint，不是 kprobe？**

- **tracepoint**：内核开发者预定义的稳定接口，位置固定，内核版本间兼容性好
- **kprobe**：可以动态插入到几乎任何内核函数入口/出口，但可能因内核版本变化而失效

对于 `execve`，tracepoint `sys_enter_execve` 是最稳定的选择。

**Q: 为什么用 Ring Buffer，不是 Perf Buffer？**

- **Perf Buffer**：每个 CPU 一个缓冲区，用户态需要轮询所有 CPU
- **Ring Buffer**（Linux 5.8+）：所有 CPU 共享一个缓冲区，支持批量提交，性能更好

**Q: bpf_probe_read_kernel 和 bpf_probe_read_user 的区别？**

- `bpf_probe_read_kernel()`：安全读取**内核空间**地址
- `bpf_probe_read_user()`：安全读取**用户空间**地址
- 如果混用会出错，因为内核态不能直接解引用用户态指针

---

## 3. 用户态桥梁：用 Go 加载 eBPF

现在我们要写 Go 代码，把这个 eBPF 程序加载到内核，并读取事件。

### 3.1 初始化 Go 模块

```bash
go mod init github.com/yourname/ebpf-sentinel
go get github.com/cilium/ebpf@v0.16.0
```

### 3.2 用 bpf2go 生成 Go 绑定

cilium/ebpf 提供了一个工具 `bpf2go`，可以把 C 的 eBPF 程序编译成目标文件，并生成对应的 Go 结构体。

在 `main.go` 顶部添加 go:generate 指令：

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang execve ./ebpf/execve.c
```

然后运行：
```bash
go generate ./...
```

这会生成两个文件：
- `execve_bpfel.o` —— 编译后的 eBPF 字节码
- `execve_bpfel.go` —— Go 结构体定义（包括 `execveObjects`、`execveMaps`、`execvePrograms` 等）

**为什么需要这一步？**

eBPF C 代码中的 Map 定义和 Go 代码需要共享类型信息。bpf2go 解析 C 代码中的 `SEC(".maps")` 结构，自动生成对应的 Go struct，让你可以用类型安全的方式访问 Maps。

### 3.3 编写最小加载器

创建 `main.go`（最小版本）：

```go
package main

import (
	"bytes"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// 这个结构体必须与 ebpf/execve.c 中的 struct event 完全匹配！
// 字段顺序、类型、大小必须一致，因为内核直接按二进制格式写入
type execveEvent struct {
	PID   uint32
	PPID  uint32
	Comm  [16]byte   // 对应 char comm[16]
	Argv0 [128]byte  // 对应 char argv0[128]
}

func main() {
	// 1. 移除内存锁定限制
	// eBPF 程序需要锁定内存（pin memory），默认 ulimit 可能不够
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	// 2. 加载 eBPF 对象
	// loadExecveObjects 是 bpf2go 生成的函数
	var objs execveObjects
	if err := loadExecveObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load execve objects: %v", err)
	}
	defer objs.Close() // 程序退出时自动清理

	// 3. 挂载到 tracepoint
	// 第一个参数是子系统名，第二个是 tracepoint 名，第三个是 eBPF 函数
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		objs.TracepointExecve, nil)
	if err != nil {
		log.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer tp.Close()

	// 4. 打开 Ring Buffer 读取器
	// objs.Events 就是 C 代码中定义的 "events" map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	log.Println("Monitoring execve syscalls...")

	// 5. 读取事件循环
	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("failed to read: %v", err)
			continue
		}

		// 6. 解析二进制数据
		// 方法 A：用 unsafe 直接映射（最快，零拷贝）
		var event execveEvent
		if len(record.RawSample) >= 152 { // 4+4+16+128 = 152 字节
			copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)
		}

		// 把字节数组转成字符串（去掉末尾的 \0）
		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		argv0 := string(bytes.Trim(event.Argv0[:], "\x00"))

		fmt.Printf("[EXECVE] PID=%d PPID=%d Comm=%s Argv0=%s\n",
			event.PID, event.PPID, comm, argv0)
	}
}
```

### 3.4 编译运行

```bash
go build .
sudo ./ebpf-sentinel
```

在另一个终端执行几个命令：
```bash
ls
ps aux
date
```

你应该能看到输出：
```
[EXECVE] PID=12345 PPID=12344 Comm=ls Argv0=/usr/bin/ls
[EXECVE] PID=12346 PPID=12344 Comm=ps Argv0=/usr/bin/ps
```

### 3.5 数据解析的两种方式

在上面的代码中，我用了两种解析方式：

**方式 A：unsafe + copy（零拷贝，最快）**
```go
copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)
```
直接把二进制数据拷贝到结构体的内存布局上。要求 Go struct 和 C struct 的内存布局完全一致。

**方式 B：binary.LittleEndian（更安全，推荐用于复杂结构）**
```go
event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
event.PPID = binary.LittleEndian.Uint32(record.RawSample[4:8])
// ...
```
显式指定字节序和偏移量，不容易出错。网络相关的 eBPF 程序中我推荐这种方式。

---

## 4. 数据持久化：SQLite + GORM

现在事件只在终端打印，我们希望保存到数据库中。

### 4.1 添加依赖

```bash
go get gorm.io/gorm gorm.io/driver/sqlite
```

### 4.2 定义数据模型

创建 `internal/models/event.go`：

```go
package models

import (
	"time"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ExecveEvent —— GORM 模型
// 结构体标签 `gorm:"..."` 告诉 GORM 如何映射到数据库列
type ExecveEvent struct {
	ID        uint64    `json:"id" gorm:"primaryKey"`  // 自增主键
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	Argv0     string    `json:"argv0"`
	CreatedAt time.Time `json:"created_at"`
}

// 全局数据库连接
var DB *gorm.DB

// InitDB 初始化 SQLite 数据库
func InitDB() (*gorm.DB, error) {
	// 打开/创建 sentinel.db 文件
	db, err := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// AutoMigrate：如果表不存在则创建；如果字段变了则更新
	// 非常方便，开发阶段不需要手动写 SQL
	err = db.AutoMigrate(&ExecveEvent{})
	if err != nil {
		return nil, err
	}

	DB = db
	return db, nil
}

// CreateEvent 保存事件
func CreateEvent(event *ExecveEvent) error {
	return DB.Create(event).Error
}

// GetRecentEvents 获取最近的 N 条事件
func GetRecentEvents(limit int) ([]ExecveEvent, error) {
	var events []ExecveEvent
	// Order("created_at desc") = 按时间倒序
	// Limit(limit) = 最多返回 limit 条
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}
```

### 4.3 为什么用 SQLite？

- **零配置**：不需要安装/启动数据库服务
- **单文件**：整个数据库就是一个 `.db` 文件
- **够用**：监控事件是写入密集型、查询轻量型，SQLite 完全胜任
- **嵌入式**：适合单节点部署的监控工具

### 4.4 在 main.go 中使用

```go
func main() {
	// 初始化数据库（放在 eBPF 加载之前）
	_, err := models.InitDB()
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	log.Println("Database initialized")

	// ... eBPF 加载代码 ...

	// 在事件处理中保存到数据库
	dbEvent := &models.ExecveEvent{
		PID:   event.PID,
		PPID:  event.PPID,
		Comm:  comm,
		Argv0: argv0,
	}
	if err := models.CreateEvent(dbEvent); err != nil {
		log.Printf("failed to save event: %v", err)
	}
}
```

---

## 5. 实时推送：WebSocket 广播

我们想在前端网页上实时看到事件。HTTP 轮询效率低，WebSocket 是最佳选择。

### 5.1 添加依赖

```bash
go get github.com/gorilla/websocket
```

### 5.2 理解 Hub 模式

WebSocket 的经典设计模式：

```
                     ┌─────────────┐
   新连接 ─────────→ │   Hub       │ ←─── 广播消息
                     │             │
   断开连接 ───────→ │ ┌─────────┐ │
                     │ │ Client  │ │ ←──→ WebSocket 连接
                     │ │ Client  │ │
                     │ │ Client  │ │
                     │ └─────────┘ │
                     └─────────────┘
```

- **Hub**：中央调度器，管理所有客户端
- **Client**：一个 WebSocket 连接对应一个 Client
- **broadcast channel**：任何组件可以往这里发消息，Hub 负责转发给所有 Client

### 5.3 实现 Hub

创建 `internal/websocket/hub.go`：

```go
package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// Hub 管理所有 WebSocket 客户端
type Hub struct {
	clients    map[*Client]bool // 已连接的客户端
	broadcast  chan []byte      // 广播消息队列
	register   chan *Client     // 注册新客户端
	unregister chan *Client     // 注销客户端
	mu         sync.RWMutex     // 保护 clients map
}

// Client 表示一个 WebSocket 连接
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte // 发送消息的缓冲通道
}

// upgrader 把 HTTP 连接升级为 WebSocket
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 开发环境允许所有来源
	},
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run 启动 Hub 主循环 —— 必须在独立的 goroutine 中运行！
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("[WebSocket] Client connected, total: %d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("[WebSocket] Client disconnected, total: %d", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// 客户端消费太慢，关闭它
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast 广播消息给所有客户端
// data 会被自动序列化为 JSON
func (h *Hub) Broadcast(data interface{}) {
	message, err := json.Marshal(data)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal: %v", err)
		return
	}

	// 非阻塞发送，如果 channel 满了则丢弃
	select {
	case h.broadcast <- message:
	default:
		log.Println("[WebSocket] Broadcast channel full, dropping")
	}
}

// ServeWs 处理 WebSocket 升级请求
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	// 升级 HTTP → WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Upgrade error: %v", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	h.register <- client

	// 每个客户端启动两个 goroutine：
	// - writePump：从 send channel 读消息，写入 WebSocket
	// - readPump：从 WebSocket 读消息（这里客户端只接收，所以只是维持连接）
	go client.writePump()
	go client.readPump()
}

// readPump 持续读取客户端消息
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// writePump 持续向客户端发送消息
func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// channel 被关闭
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		}
	}
}
```

### 5.4 为什么需要两个 goroutine  per client？

WebSocket 连接是双向的：
- **readPump**：必须持续读取，否则对方发消息时连接会被关闭
- **writePump**：从 channel 读消息写入连接

分离成两个 goroutine 避免了读写互相阻塞。这是 gorilla/websocket 推荐的标准模式。

### 5.5 在事件发生时广播

```go
// 在 eBPF 事件处理中：
hub.Broadcast(map[string]interface{}{
	"type": "execve",
	"data": map[string]interface{}{
		"pid":   event.PID,
		"ppid":  event.PPID,
		"comm":  comm,
		"argv0": argv0,
	},
})
```

---

## 6. HTTP API：Gin 路由层

我们需要 REST API 供前端查询历史数据、管理策略。

### 6.1 添加依赖

```bash
go get github.com/gin-gonic/gin
```

### 6.2 设置路由

```go
func setupRoutes(r *gin.Engine, hub *websocket.Hub) {
	// 查询最近事件
	r.GET("/api/events", func(c *gin.Context) {
		events, err := models.GetRecentEvents(100)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, events)
	})

	// WebSocket 端点
	r.GET("/ws", func(c *gin.Context) {
		hub.ServeWs(c.Writer, c.Request)
	})

	// 静态文件服务
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/", "./web/dist/index.html")
}
```

### 6.3 为什么用 Gin？

- **路由简洁**：`r.GET("/path", handler)` 比标准库的 `http.HandleFunc` 更直观
- **参数绑定**：`c.ShouldBindJSON(&req)` 自动解析 JSON 请求体
- **中间件**：内置 Logger、Recovery 中间件
- **性能**：基于 httprouter，路由匹配是 O(1)

---

## 7. 可视化：单页 Dashboard

前端 intentionally 是单个 HTML 文件，不依赖任何构建工具。

### 7.1 创建前端文件

创建 `web/dist/index.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>eBPF Sentinel</title>
    <style>
        body {
            font-family: -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border-bottom: 1px solid #334155; text-align: left; }
        th { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }
        tr:hover { background: #334155; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }
        .badge-execve { background: #3b82f6; }
        .pid { color: #f472b6; font-family: monospace; }
        .comm { color: #4ade80; }
    </style>
</head>
<body>
    <div class="container">
        <h1>eBPF Sentinel</h1>
        <p>连接状态: <span id="status">连接中...</span></p>
        <table>
            <thead>
                <tr><th>类型</th><th>时间</th><th>PID</th><th>进程</th><th>命令</th></tr>
            </thead>
            <tbody id="events"></tbody>
        </table>
    </div>

    <script>
        let ws;
        function connect() {
            ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onopen = () => document.getElementById('status').textContent = '已连接';
            ws.onmessage = (e) => {
                const msg = JSON.parse(e.data);
                if (msg.type === 'execve') addEvent(msg.data);
            };
            ws.onclose = () => {
                document.getElementById('status').textContent = '已断开，3秒后重连';
                setTimeout(connect, 3000);
            };
        }

        function addEvent(data) {
            const tbody = document.getElementById('events');
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="badge badge-execve">execve</span></td>
                <td>${new Date().toLocaleTimeString()}</td>
                <td class="pid">${data.pid}</td>
                <td class="comm">${data.comm}</td>
                <td>${data.argv0}</td>
            `;
            tbody.insertBefore(row, tbody.firstChild);
            while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
        }

        connect();
    </script>
</body>
</html>
```

### 7.2 为什么不用 React/Vue？

- 这个项目的前端只是**数据显示面板**，没有复杂状态管理
- 单文件 HTML 部署最简单，不需要 npm install、webpack、构建步骤
- 直接操作 DOM 对于 100 行左右的逻辑完全够用
- 零依赖 = 零维护负担

---

## 8. 扩展网络监控

进程监控已经工作了。现在加网络监控：捕获所有进出系统的网络包。

### 8.1 eBPF 网络程序的挂载点

网络监控用 **TC（Traffic Control）** 挂载点：
- **TC Ingress**：数据包进入系统时触发
- **TC Egress**：数据包离开系统时触发

新版内核（5.18+）推荐使用 **TCX**，比传统 TC 更灵活。

### 8.2 编写 network.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

struct net_event {
    u32 pid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 direction;
    u32 packet_size;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// 解析数据包的共用函数
static __always_inline int process_packet(struct __sk_buff *skb, u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 边界检查：防止访问超出数据包范围
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;

    // 只处理 IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return 0;

    void *ip_data = data + ETH_HLEN;
    struct iphdr *ip = ip_data;
    if ((void *)(ip + 1) > data_end) return 0;

    u8 protocol = ip->protocol;
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP) return 0;

    // 提取端口
    u8 ip_header_len = ip->ihl * 4;
    void *transport = ip_data + ip_header_len;

    u16 src_port = 0, dst_port = 0;
    if (protocol == IP_PROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end) return 0;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end) return 0;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    // 创建事件
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->src_ip = bpf_ntohl(ip->saddr);
    e->dst_ip = bpf_ntohl(ip->daddr);
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = protocol;
    e->direction = direction;
    e->packet_size = skb->len;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Ingress 程序
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    process_packet(skb, 0);
    return 0; // 放行数据包，不拦截
}

// Egress 程序
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    process_packet(skb, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 8.3 Go 中挂载 TCX

```go
// attachNetworkProgram 挂载网络程序到指定接口
func attachNetworkProgram(objs *networkObjects, ifaceIdx int, isIngress bool) (link.Link, error) {
	var prog *ebpf.Program
	var attachType ebpf.AttachType

	if isIngress {
		prog = objs.TcIngress
		attachType = ebpf.AttachTCXIngress
	} else {
		prog = objs.TcEgress
		attachType = ebpf.AttachTCXEgress
	}

	tcxOpts := link.TCXOptions{
		Interface: ifaceIdx,
		Program:   prog,
		Attach:    attachType,
	}
	return link.AttachTCX(tcxOpts)
}

// 获取所有活动接口并挂载
interfaces := getNetworkInterfaces()
for _, iface := range interfaces {
	ingressLink, _ := attachNetworkProgram(networkObjs, iface.Index, true)
	egressLink, _ := attachNetworkProgram(networkObjs, iface.Index, false)
	// ...
}
```

### 8.4 关键设计决策

**Q: 为什么返回 0 而不是丢弃数据包？**

TC 程序可以决定数据包的命运：
- `return 0`（或 `TC_ACT_OK`）：放行数据包
- `return 2`（`TC_ACT_SHOT`）：丢弃数据包

我们是**监控**工具，不是防火墙，所以始终放行。

**Q: 为什么要同时挂载 ingress 和 egress？**

- **ingress**：看到进入系统的数据包（下载）
- **egress**：看到离开系统的数据包（上传）
- 只挂载一个会丢失一半的信息

---

## 9. 扩展 CPU 监控

CPU 监控用 `sched/sched_switch` tracepoint，在每次进程切换时计算 CPU 时间。

### 9.1 cpu.c

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct cpu_stat {
    u64 busy_ns;    // 非 idle 时间（纳秒）
    u64 idle_ns;    // idle 时间（纳秒）
    u64 last_ts;    // 上次切换时间戳
    u32 is_busy;    // 当前是否 busy
};

// PERCPU_ARRAY：每个 CPU 核心一份独立数据，无锁访问
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_stat);
} cpu_stats SEC(".maps");

SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u32 key = 0;
    struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &key);
    if (!stat) return 0;

    u64 now = bpf_ktime_get_ns();

    // 计算从上一次到现在的时间差
    if (stat->last_ts > 0) {
        u64 delta = now - stat->last_ts;
        if (stat->is_busy) {
            stat->busy_ns += delta;
        } else {
            stat->idle_ns += delta;
        }
    }

    // next_pid == 0 表示切换到 idle 进程
    stat->is_busy = (ctx->next_pid != 0) ? 1 : 0;
    stat->last_ts = now;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 9.2 Go 中读取 CPU 统计

```go
func getCPUUsage() float64 {
	var key uint32 = 0
	var stats []cpuCpuStat // PERCPU_ARRAY 返回每个 CPU 的数据
	
	if err := cpuObjs.CpuStats.Lookup(key, &stats); err != nil {
		return 0
	}

	var totalBusy, totalIdle float64
	for i, stat := range stats {
		deltaBusy := float64(stat.BusyNs - cpuPrevBusy[i])
		deltaIdle := float64(stat.IdleNs - cpuPrevIdle[i])
		totalBusy += deltaBusy
		totalIdle += deltaIdle
		cpuPrevBusy[i] = stat.BusyNs
		cpuPrevIdle[i] = stat.IdleNs
	}

	total := totalBusy + totalIdle
	if total <= 0 { return 0 }
	return (totalBusy / total) * 100
}
```

---

## 10. 完整整合与运行

### 10.1 项目最终结构

```
ebpf-sentinel/
├── main.go                          # 入口：加载所有 eBPF，启动服务
├── go.mod                           # Go 模块定义
├── ebpf/
│   ├── execve.c                     # 进程监控 eBPF
│   ├── network.c                    # 网络监控 eBPF
│   ├── cpu.c                        # CPU 监控 eBPF
│   └── vmlinux.h                    # 内核类型定义
├── internal/
│   ├── models/
│   │   └── event.go                 # GORM 模型 + 数据库操作
│   ├── websocket/
│   │   └── hub.go                   # WebSocket Hub
│   └── plugin/
│       └── plugin.go                # 插件接口
└── web/dist/
    └── index.html                   # 前端 Dashboard
```

### 10.2 main.go 主流程

```
main()
├── InitDB()              初始化 SQLite
├── NewHub() / Run()      启动 WebSocket Hub
├── remove memlock        解除内存限制
├── loadExecveObjects()   加载 execve eBPF
├── link.Tracepoint()     挂载 execve tracepoint
├── ringbuf.NewReader()   打开 Ring Buffer
├── 启动 goroutine        读取 execve 事件 → DB + WebSocket
├── loadNetworkObjects()  加载 network eBPF
├── AttachTCX()           挂载到所有网络接口
├── 启动 goroutine        读取网络事件 → DB + WebSocket
├── loadCpuObjects()      加载 CPU eBPF
├── link.Tracepoint()     挂载 sched_switch
├── gin.Default()         创建 HTTP 服务器
├── setupRoutes()         注册路由
└── r.Run(":8080")        启动服务
```

### 10.3 构建运行

```bash
# 1. 生成 eBPF Go 绑定
go generate ./...

# 2. 编译
go build .

# 3. 运行（需要 root）
sudo ./ebpf-sentinel

# 4. 打开浏览器
# http://localhost:8080
```

---

## 11. 进阶话题

### 11.1 网络监控中的白名单机制

**方案 A：Go 中过滤（简单但低效）**
```go
if isInWhitelist(comm) { continue }
```
- 缺点：每个事件都要从内核传到用户态，浪费带宽

**方案 B：eBPF Map 中过滤（高效）**
```c
// network.c 中的 IP/端口白名单
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} ip_whitelist SEC(".maps");

// 在 eBPF 中检查
if (!is_ip_whitelisted(src_ip)) {
    return 0;  // 不在白名单中，跳过
}
```
- 优点：被过滤的事件根本不出内核，零开销
- 更新白名单：`objs.IpWhitelist.Update(key, value, flags)`

**注意**: execve.c 不再使用白名单过滤，所有进程事件都会被捕获。

### 11.2 采样策略

高流量场景下，不需要捕获每个包：

```c
#define SAMPLE_RATE 100

static __always_inline bool should_sample(u32 direction) {
    u64 *counter = bpf_map_lookup_elem(&sample_counter, &direction);
    u64 new_val = counter ? *counter + 1 : 1;
    bpf_map_update_elem(&sample_counter, &direction, &new_val, BPF_ANY);
    return (new_val % SAMPLE_RATE) == 0;
}
```
每 100 个包只采样 1 个，显著降低事件量。

### 11.3 优雅降级

网络监控可能因权限、内核版本等原因失败，不应该导致整个程序崩溃：

```go
if err := loadNetworkObjects(networkObjs, nil); err != nil {
    log.Printf("[network] failed to load: %v", err)
    log.Println("[network] Network monitoring disabled")
} else {
    // 正常初始化网络监控
}
```

### 11.4 eBPF Verifier 常见陷阱

- **空指针检查**：每次解引用前必须检查指针是否为 NULL
- **边界检查**：访问数据包时必须确认不会越界
- **循环限制**：eBPF 传统上不允许无限循环（有界循环需要内核 5.3+）
- **栈限制**：eBPF 程序栈空间只有 512 字节，大结构体要用 Map

---

## 总结

你现在已经理解了 eBPF-Sentinel 的每一层：

| 层级 | 技术 | 职责 |
|------|------|------|
| 内核 | eBPF C | 捕获系统事件（进程、网络、CPU） |
| 加载 | cilium/ebpf + bpf2go | 编译、加载、管理 eBPF 程序 |
| 处理 | Go | 读取 Ring Buffer、解析事件 |
| 存储 | GORM + SQLite | 持久化事件数据 |
| 实时 | Gorilla WebSocket | 推送事件到前端 |
| API | Gin | 提供 REST 接口 |
| 展示 | HTML/CSS/JS | 可视化 Dashboard |

每个层级都可以独立扩展：
- 加新监控？写个新的 `.c` 文件 + Go 加载代码
- 改存储？换 GORM 的 driver（MySQL、PostgreSQL）
- 改前端？替换 `web/dist/index.html`

---

## 参考

- [cilium/ebpf 文档](https://pkg.go.dev/github.com/cilium/ebpf)
- [eBPF 概念介绍](https://ebpf.io/what-is-ebpf)
- [Gin 框架文档](https://gin-gonic.com/docs/)
- [GORM 指南](https://gorm.io/docs/)
- [Gorilla WebSocket](https://github.com/gorilla/websocket)
