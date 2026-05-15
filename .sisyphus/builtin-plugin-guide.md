# eBPF-Sentinel 内置功能开发指南

> 适用范围: 新增内置功能插件，也就是把功能作为 Go 代码放进本仓库，并在 `main.go` 中注册。
> 不适用范围: 外部插件、运行时动态加载、第三方插件市场。

---

## 一、当前插件化模型

新增内置功能的基本路径是:

```text
eBPF C 程序/普通 Go 采集逻辑
  -> internal/plugin/xxx_plugin.go
  -> plugin.Event
  -> main.dispatchPluginEvents()
  -> persistEvent()
  -> WebSocket 广播
  -> 前端展示/API 查询
```

当前插件统一实现 `internal/plugin.Plugin` 接口:

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

如果插件需要运行时开关，还应实现:

```go
type PolicyControl interface {
    IsEnabled() bool
    SetEnabled(bool) error
}
```

现有参考实现:

- `internal/plugin/execve_plugin.go`: tracepoint + ringbuf + policy map
- `internal/plugin/network_plugin.go`: TC hook + ringbuf + whitelist maps
- `internal/plugin/cpu_plugin.go`: eBPF map 读取，不直接产生事件
- `internal/plugin/system_plugin.go`: 纯用户态定时采集，产生 system 事件

---

## 二、先判断新增功能属于哪一类

### 1. 事件型 eBPF 插件

适合文件访问、DNS、连接建立、进程退出等事件。

特征:

- 需要写 `ebpf/xxx.c`
- 通过 ringbuf/perf buffer 输出事件
- Go 插件负责 Load、Attach、Read、解析事件
- 最终发送 `plugin.Event`

### 2. 指标型 eBPF 插件

适合 CPU、内存、调度、计数器类指标。

特征:

- eBPF 侧写 Map
- Go 侧定期读取 Map
- 可以不直接往 `eventChan` 写事件，而是提供回调给其他插件

`CPUPlugin` 就是这种模式。

### 3. 纯 Go 插件

适合不需要 eBPF 的系统信息、聚合统计、健康检查。

特征:

- 不需要 `bpf2go`
- `Load()`/`Attach()` 可以只初始化状态
- `Start()` 中用 ticker 定时发送事件

`SystemMonitorPlugin` 就是这种模式。

---

## 三、推荐开发流程

### Step 1: 定义事件契约

先确定插件输出的 `plugin.Event` 格式。

示例:

```go
&plugin.Event{
    Type: "file",
    Timestamp: time.Now().Unix(),
    Data: map[string]interface{}{
        "pid": pid,
        "comm": comm,
        "path": path,
        "op": op,
    },
}
```

要求:

- `Type` 必须稳定、唯一、简短，例如 `file`、`dns`、`conn`
- `Data` 字段类型要稳定，避免同一字段有时是 string、有时是 number
- 如果要入库，字段要能映射到 GORM model
- 如果要前端展示，字段名尽量直接可读

### Step 2: 如果需要 eBPF，新增 C 程序

新增文件:

```text
ebpf/xxx.c
```

一般结构:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct xxx_event {
    u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} xxx_events SEC(".maps");

SEC("tp/...")
int tracepoint_xxx(...) {
    struct xxx_event *e = bpf_ringbuf_reserve(&xxx_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

注意:

- eBPF C struct 和 Go 侧 binary struct 必须二进制对齐
- 字符串使用固定长度数组，例如 `[16]byte`、`[128]byte`
- 复杂结构优先在 Go 侧解析，eBPF 侧保持简单
- 不要修改已有 `*_bpfel.go` 生成文件

### Step 3: 生成 bpf2go 绑定

在仓库已有生成模式基础上，为新 C 文件添加 `go:generate` 入口。

建议新增一个生成文件，例如:

```text
xxx_generate.go
```

内容示例:

```go
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xxx ebpf/xxx.c
```

然后执行:

```bash
go generate ./...
```

生成结果一般会包含:

```text
xxx_bpfel.go
xxx_bpfel.o
```

规则:

- 生成文件位于 `main` package
- 不要把生成文件移动到 `internal/plugin`
- 插件包通过 `BPFCollectionProvider` 桥接加载函数

### Step 4: 在 plugin 包定义二进制事件结构

如果是 ringbuf 事件，在:

```text
internal/plugin/types.go
```

增加对应结构体和大小常量。

示例:

```go
const FileEventSize = 148

type FileEventBinary struct {
    PID  uint32
    Comm [16]byte
    Path [128]byte
}
```

要求:

- 字段顺序必须与 C struct 一致
- 手动计算 size，必要时考虑 padding
- 对齐复杂时使用 `binary.LittleEndian` 手动解析，不要强行 unsafe

### Step 5: 新建 Go 插件实现

新增:

```text
internal/plugin/xxx_plugin.go
```

事件型插件最小结构:

```go
type XxxPlugin struct {
    BasePlugin
    provider BPFCollectionProvider
    objs     *xxxObjects
    reader   *ringbuf.Reader
    enabled  atomic.Bool
}
```

插件内部定义自己的 objects 结构，字段 tag 对应 bpf2go 生成的 map/program 名:

```go
type xxxObjects struct {
    TracepointXxx *ebpf.Program `ebpf:"tracepoint_xxx"`
    XxxEvents     *ebpf.Map     `ebpf:"xxx_events"`
    XxxEnabled    *ebpf.Map     `ebpf:"xxx_enabled"`
}
```

实现重点:

- `Load()`: `rlimit.RemoveMemlock()`，调用 provider 加载 objects
- `Attach()`: 挂载 tracepoint/kprobe/tc，并保存 `link.Link`
- `Start()`: 阻塞读取 ringbuf，解析后发送 `plugin.Event`
- `Detach()`: 关闭 links
- `Close()`: 关闭 reader、links、objects
- `SetEnabled()`: 如果有 eBPF 开关 Map，要同步 Map 和 `atomic.Bool`

### Step 6: 在 main.go 增加 provider 和注册

因为 bpf2go 生成代码在 `main` package，新插件需要一个 provider adapter。

在 `main.go` 中增加:

```go
type xxxBPFProvider struct{}

func (xxxBPFProvider) LoadAndAssign(obj interface{}, opts *ebpf.CollectionOptions) error {
    return loadXxxObjects(obj, opts)
}
```

然后在启动流程里注册:

```go
xxxPlugin := plugin.NewXxxPlugin(xxxBPFProvider{})
registerPlugin(manager, xxxPlugin)
```

如果插件有策略开关，还需要决定是否:

- 新增独立策略函数，例如 `isXxxMonitoringEnabled()`
- 或未来迁移到通用插件策略 API

目前已有通用插件管理器，但策略 API 还是固定的 execve/network 风格。

### Step 7: 接入事件持久化

如果新事件需要落库，修改:

```text
internal/models/event.go
main.go -> persistEvent()
routes.go
```

流程:

1. 在 `internal/models/event.go` 增加 GORM model
2. 在 `InitDB()` 的 `AutoMigrate()` 加入新 model
3. 增加 `CreateXxxEvent()` 和 `GetRecentXxxEvents()`
4. 在 `main.go` 的 `persistEvent()` 增加 `case "xxx"`
5. 在 `routes.go` 增加查询 API，例如 `/api/xxx-events`

如果只是实时展示，不需要历史查询，可以先不落库，但要明确这是设计选择。

### Step 8: 接入前端展示

前端目前是静态文件:

```text
web/dist/index.html
web/dist/assets/app.js
web/dist/assets/app.css
```

需要做的事:

- 在 `app.js` 的 `handleEvent()` 中识别新 `event.type`
- 新增事件数组，例如 `xxxEvents`
- 新增 render 函数
- 在 `index.html` 增加 tab/table 或复用总览表
- 在 `app.css` 增加 badge/表格样式

如果只希望先验证后端，可以先让新事件显示在 “all events” 中，再补专门面板。

### Step 9: 验证

每次新增内置插件至少跑:

```bash
GOCACHE=/tmp/go-build go build -o /tmp/eBPF-Sentinel .
GOCACHE=/tmp/go-build go test ./...
GOCACHE=/tmp/go-build go vet ./...
```

运行验证:

```bash
sudo /tmp/eBPF-Sentinel
curl http://localhost:8080/api/policy/status
```

如果是事件型插件:

- 触发对应系统行为
- 看 WebSocket 是否收到事件
- 看 API 是否能查到历史事件
- 关闭策略后确认事件停止

如果非 root 运行:

- eBPF 插件允许加载失败
- HTTP 服务仍应启动
- system 插件仍应工作

---

## 四、文件修改清单模板

新增一个 eBPF 事件型内置功能时，通常会改这些文件:

```text
ebpf/xxx.c                              # 新增 eBPF 程序
xxx_generate.go                         # 新增 go:generate 指令
xxx_bpfel.go / xxx_bpfel.o              # go generate 生成，勿手动编辑
internal/plugin/types.go                # 增加 binary event struct
internal/plugin/xxx_plugin.go           # 新增插件实现
main.go                                 # 增加 provider + manager.Register
internal/models/event.go                # 如需持久化，增加 model
routes.go                               # 如需查询 API，增加 route
web/dist/assets/app.js                  # 如需前端展示，处理新事件
web/dist/index.html                     # 如需独立面板，增加 DOM
web/dist/assets/app.css                 # 如需样式，增加 CSS
```

新增一个纯 Go 内置功能时，通常只需要:

```text
internal/plugin/xxx_plugin.go
main.go
internal/models/event.go                # 可选
routes.go                               # 可选
web/dist/...                            # 可选
```

---

## 五、最小示例: 新增纯 Go 心跳插件

适合用来验证插件流程，不涉及 eBPF。

```go
type HeartbeatPlugin struct {
    BasePlugin
    ctx    context.Context
    cancel context.CancelFunc
}

func NewHeartbeatPlugin() *HeartbeatPlugin {
    return &HeartbeatPlugin{
        BasePlugin: BasePlugin{
            Name_: "heartbeat",
            Description_: "Emit periodic heartbeat events",
        },
    }
}

func (p *HeartbeatPlugin) Load() error { return nil }

func (p *HeartbeatPlugin) Attach() error {
    p.ctx, p.cancel = context.WithCancel(context.Background())
    return nil
}

func (p *HeartbeatPlugin) Detach() error {
    if p.cancel != nil {
        p.cancel()
    }
    return nil
}

func (p *HeartbeatPlugin) Close() error { return p.Detach() }

func (p *HeartbeatPlugin) Start(eventChan chan<- *Event) error {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-p.ctx.Done():
            return nil
        case <-ticker.C:
            eventChan <- &Event{
                Type: "heartbeat",
                Timestamp: time.Now().Unix(),
                Data: map[string]interface{}{
                    "status": "ok",
                },
            }
        }
    }
}
```

注册:

```go
heartbeatPlugin := plugin.NewHeartbeatPlugin()
registerPlugin(manager, heartbeatPlugin)
```

---

## 六、常见坑

1. `plugin` 包不能 import `main` 包  
   bpf2go loader 要通过 provider 从 `main.go` 注入。

2. 不要手改 `*_bpfel.go`  
   修改 eBPF C 后重新 `go generate`。

3. ringbuf 读取必须只由一个 goroutine 负责  
   `Start()` 本身是阻塞函数，`Manager.StartAll()` 会给每个插件开 goroutine。

4. 策略开关不能只改前端  
   至少要改插件内的 `atomic.Bool`，最好同步到 eBPF Map。

5. 新事件不会自动入库  
   必须在 `persistEvent()` 增加 `case`，并在 models 中建表。

6. 前端总览不是通用事件渲染器  
   当前 `app.js` 对 `execve/network/system` 有硬编码，新类型需要补渲染逻辑。

7. eBPF 加载失败不应拖垮 HTTP 服务  
   插件 `Load()`/`Attach()` 返回错误即可，`Manager` 会记录日志并跳过。

---

## 七、完成标准

新增内置功能完成时，应满足:

- `go build` 通过
- `go test ./...` 通过
- `go vet ./...` 通过
- 非 root 启动时 HTTP 服务仍可用
- root 启动时插件能加载并产生预期数据
- 策略关闭后不再产生或执行对应功能
- WebSocket 事件格式稳定
- 如需持久化，API 能查询历史事件
