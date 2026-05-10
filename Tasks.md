# Overview

Project name: eBPF-Sentinel

## 核心架构

A. 内核态-采集插件层
    - 技术: eBPF, LLVM/Clang
    - 职责: 通过`kprobes` or `tracepoints` 钩住系统调用
        - 使用eBPF Maps储存统计数据
        - 使用Ring Buffer将实时事件异步发送到用户态
B. 用户态-控制与逻辑层
    - 技术: Go语言, `cilium/ebpf` 库
    - 职责:
        - 加载器 (Loader)： 负责将编译好的 eBPF 字节码加载进内核。
        - bpf2go 转换： 自动生成 Go 结构体，直接读取内核传来的二进制数据。
        - 插件管理器： 动态控制不同监控模块（进程监控、网络监控、文件监控）的启停。
        - API 服务 (Gin)： 提供 RESTful 接口，并将 Ring Buffer 的数据转化为 JSON。

C. 表现层-可视化面板
    - 技术： Next.js (推荐, 路由简单且性能好), Tailwind CSS, Recharts (图表库)。
    - 职责：
        - Dashboard： 展示系统负载、进程总数等概览。
        - 实时流 (Live Feed)： 展示系统调用的实时流水（类似 strace 的可视化版）。
        - 关系图： 展示进程间的父子关系和文件访问链路。

### 第一阶段: 最小可行性产品

1. 环境准备: Linux系统、clang、go、llvm
2. 写一个简单的C程序： 监控`execve`系统调用: 每次有新进程启动时打印一次
3. 使用bpf2go, 运行`go generate`生成Go绑定代码
4. Go主程序, 调用生成的代码,将eBPF程序挂载到内核, 并在终端打印数据.

### 第二阶段: 引入Gin后端与可视化

1. 数据转换, 将终端打印的数据存入简单的数据库(SQLite)
2. API暴露, 使用Gin写GET接口, 返回最近的100条系统调用
3. 前端接入, 写一个简单的react页面,每隔一秒请求一次API并展示在页面中.

### 第三阶段: 插件化与高级功能

1. 定义Plugin接口, 统一eBPF程序加载和读取逻辑
2. 引入WebSocket, 为了性能检测的实时性,放弃轮询,改用WebSocket实时推送内核事件.

---

添加/改造新功能:

第四阶段：交互式响应与治理

    策略下发: 实现前端修改 BPF Maps 的功能，支持动态设置监控白名单。

    进程治理: 在前端 Live Feed 增加“终止进程”按钮，通过 API 调用系统信号实现闭环控制。

    拓扑交互: 展示进程-文件-网络的关联链路图，点击节点可查看详细行为轨迹。
