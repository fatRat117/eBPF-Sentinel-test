# eBPF-Sentinel 插件化改造建议

## 当前状态判断

项目已经具备插件化的雏形：

- `internal/plugin/plugin.go` 定义了统一的 `Plugin` 接口和 `Manager`
- `SystemMonitorPlugin` 已经按插件方式运行
- 文档中也把 `Execve`、`Network`、`System` 描述为插件层能力

但当前运行时还没有真正完成插件化：

- `main.go` 仍直接调用 `startEBPFMonitors`
- `execve` 与 `network` 仍由 `monitor_runtime.go` 手工加载、挂载和消费事件
- `ExecvePlugin` 仍是占位实现，没有真正接入 bpf2go 生成对象
- 还没有 `NetworkPlugin`
- `Plugin Manager` 没有成为系统唯一的生命周期入口

因此，后续若希望通过插件扩展项目能力，建议先完成“插件框架落地”，再继续堆叠更多功能。

## 插件化前必须完成的改造

### 1. 统一运行时入口

建议把以下逻辑迁移到插件层：

- eBPF 对象加载
- 程序挂载
- Ring Buffer 读取
- 事件标准化
- 生命周期清理

主程序只保留：

- 初始化数据库
- 初始化 WebSocket / HTTP
- 初始化 `PluginManager`
- 注册默认插件
- 启动统一事件总线

### 2. 补齐核心插件

至少补齐三个一等公民插件：

- `ExecvePlugin`
- `NetworkPlugin`
- `SystemMonitorPlugin`

其中：

- `ExecvePlugin` 负责进程执行事件
- `NetworkPlugin` 负责网络事件和白名单 Map 管理
- `SystemMonitorPlugin` 负责 CPU、网速、负载等周期指标

### 3. 统一事件与存储模型

当前事件处理存在两条路径：

- 内置监控直接写数据库并推 WebSocket
- 插件事件只推 WebSocket

建议引入统一的事件处理链：

1. 插件产生标准事件
2. Event Processor 做过滤、规则判断、持久化和广播
3. 存储层按事件类型落库

建议新增：

- `EventEnvelope`
- `EventProcessor`
- `EventRepository`
- `EventRouter`

### 4. 插件配置与能力声明

建议每个插件提供：

- `Name`
- `Description`
- `Version`
- `Capabilities`
- `DefaultConfig`
- `ValidateConfig`
- `ReloadConfig`

配置来源可以先用本地文件，后续再接数据库或 API。

### 5. 插件生命周期管理 API

建议新增管理接口：

- `GET /api/plugins`
- `GET /api/plugins/:name`
- `POST /api/plugins/:name/enable`
- `POST /api/plugins/:name/disable`
- `POST /api/plugins/:name/reload`
- `PUT /api/plugins/:name/config`

这样前端策略页才能从“固定两个开关”升级为“插件控制台”。

### 6. BPF Map 控制面统一化

当前策略开关主要发生在用户态，eBPF 侧的 Map 没有形成统一控制面。

建议新增：

- `MapController`
- `PolicyStore`
- `PluginConfigSync`

用于同步：

- 监控启停状态
- 采样率
- IP / 端口白名单
- PID / UID / cgroup 过滤条件

## 推荐优先实现的插件功能

### P0: 先做，能直接补齐产品骨架

#### 1. NetworkPolicyPlugin

目标：

- 真正管理 IP 白名单、端口白名单、采样率
- 提供 API 动态下发策略
- 统一同步到 eBPF Maps

价值：

- 让现有网络监控从“可看”升级为“可控”
- 能直接修正当前策略面与运行时脱节的问题

#### 2. ProcessPolicyPlugin

目标：

- 管理 PID / PPID / 进程名 / 用户过滤条件
- 为 `execve` 事件加入黑白名单
- 提供命中策略后的告警事件

价值：

- 让进程监控具备最基础的检测能力
- 便于后续扩展审计、阻断、告警链路

#### 3. AlertPlugin

目标：

- 订阅标准事件总线
- 根据规则生成告警
- 支持严重级别、去重、抑制窗口

首批规则建议：

- 可疑命令执行
- 非预期外联
- 短时间内异常进程风暴
- 高速网络突发

价值：

- 让系统从“展示工具”变成“安全监测系统”

### P1: 第二阶段，增强可观测性

#### 4. FileActivityPlugin

目标：

- 监控敏感文件打开、写入、删除
- 关注 `/etc/passwd`、`/etc/shadow`、系统服务配置等路径

价值：

- 补齐主机审计面

#### 5. DNSMonitorPlugin

目标：

- 捕获 DNS 查询与返回
- 与进程信息关联
- 支持域名规则检测

价值：

- 能识别恶意域名访问和异常通信前兆

#### 6. ConnectionStatePlugin

目标：

- 监控 TCP connect / accept / close
- 构建进程到远端地址的连接视图

价值：

- 比“采样包事件”更适合做安全分析和资产观测

### P2: 第三阶段，面向复杂场景

#### 7. ContainerContextPlugin

目标：

- 为事件补充容器 ID、cgroup、namespace 信息

价值：

- 让项目适配容器化环境

#### 8. PersistencePlugin

目标：

- 将统一事件写入不同后端
- 支持 SQLite、PostgreSQL、Kafka 或本地 JSONL

价值：

- 把“采集”和“存储”拆开
- 便于集成外部 SIEM / 数据平台

#### 9. ExporterPlugin

目标：

- 暴露 Prometheus metrics
- 提供事件吞吐、丢弃数、插件状态、Map 同步状态

价值：

- 让系统自身可运维

## 推荐的最小落地路线

### 阶段一

1. 把 `Execve` 和 `Network` 迁入插件体系
2. 让 `PluginManager` 接管启动、关闭、错误处理
3. 引入统一 `EventProcessor`
4. 把前端策略页改成插件列表 + 配置面板

### 阶段二

1. 实现 `NetworkPolicyPlugin`
2. 实现 `ProcessPolicyPlugin`
3. 实现 `AlertPlugin`
4. 增加插件配置持久化

### 阶段三

1. 扩展文件、DNS、连接状态插件
2. 增加容器上下文
3. 增加多存储后端和指标导出

## 设计原则

- 插件只负责采集或专一处理，不直接绑死 UI
- Event Processor 负责统一过滤、持久化、广播和告警分发
- 策略控制优先同步到 eBPF Maps，避免只在用户态“假关闭”
- 所有插件必须可启停、可重载、可观测
- 新插件必须带最小测试和能力声明

