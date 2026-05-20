# eBPF-Sentinel 项目文档

欢迎来到 eBPF-Sentinel 项目文档中心！本文档库提供了项目的完整说明和学习资源。

## 文档结构

```
doc/
├── 01-project-structure/     # 项目各部分说明
├── 02-architecture-layers/   # 各个层级说明
├── 03-minimal-tutorial/      # 重点实现的最小模型
├── 04-qa/                    # Q&A 问答
├── tutorial.md               # 从零构建完整项目教程
├── critical-alert-test-guide.md  # 告警测试指南
└── README.md                 # 本文档
```

## 快速导航

### 1. 项目各部分说明
**文件**: [01-project-structure/README.md](./01-project-structure/README.md)

以文件/文件夹的粒度详细说明项目结构，包括：
- 根目录文件说明（main.go、go.mod等）
- `ebpf/` 目录（eBPF C 程序源码）
- `internal/` 目录（内部包）
- `web/` 目录（前端资源）
- 生成文件说明（*_bpfel.go、*_bpfel.o）
- 文件依赖关系图

适合：想要了解项目结构的开发者

---

### 2. 各个层级说明
**文件**: [02-architecture-layers/README.md](./02-architecture-layers/README.md)

以抽象层次说明项目架构，包括：
- 展示层（Web Frontend）
- 应用层（HTTP API、WebSocket、事件处理器）
- 插件层（Plugin 系统）
- eBPF 运行时层（cilium/ebpf 库）
- 内核层（eBPF 虚拟机、内核子系统）
- 硬件/系统层（事件源）

包含完整的数据流图和层级间交互说明。

适合：想要了解系统架构的开发者

---

### 3. 重点实现的最小模型
**文件**: [03-minimal-tutorial/README.md](./03-minimal-tutorial/README.md)

以教学为目的，从零开始构建 eBPF 监控系统的教程：
- 第一部分：eBPF Hello World
- 第二部分：获取进程信息
- 第三部分：使用 Ring Buffer 传输数据
- 第四部分：Go 用户态程序
- 第五部分：运行完整示例

包含完整的代码示例和详细的概念解释。

适合：想要学习 eBPF 开发的初学者

---

### 4. Q&A 问答
**文件**: [04-qa/README.md](./04-qa/README.md)

回答关于项目的常见问题：

1. **数据如何流动？** - 详细的数据流说明
2. **内核态在做什么？** - eBPF 程序在内核的工作
3. **用户态在做什么？** - Go 程序的职责
4. **画出数据流（文本图）** - 完整的架构图和时序图
5. **这个工具在监控什么？** - 监控内容详解
6. **eBPF 程序如何挂载，挂载在哪？** - 挂载点详解
7. **如何实现数据持久化？** - 数据库设计说明

适合：想要深入理解系统工作原理的开发者

---

### 5. 从零构建完整项目教程
**文件**: [tutorial.md](./tutorial.md)

以教学为目的，从空文件夹开始逐步构建完整监控系统：
- 从 eBPF C 代码到 Web 仪表盘的完整流程
- 包含插件架构、告警系统、安全中间件等进阶话题
- 每层技术选型的原因和设计决策

适合：想要理解完整项目构建过程的开发者

---

### 6. 告警测试指南
**文件**: [critical-alert-test-guide.md](./critical-alert-test-guide.md)

指导如何触发和验证各种告警规则：
- 反弹 Shell 告警测试（ncat 方式）
- 进程链攻击告警测试
- 数据外泄告警测试（单元测试方式）
- 常见失败原因排查

适合：想要验证告警系统功能的开发者

---

## 推荐阅读顺序

### 路径一：快速了解项目
1. [项目各部分说明](./01-project-structure/README.md) - 了解有什么
2. [Q&A: 这个工具在监控什么？](./04-qa/README.md) - 了解做什么

### 路径二：深入理解架构
1. [各个层级说明](./02-architecture-layers/README.md) - 理解架构设计
2. [Q&A: 数据流相关问答](./04-qa/README.md) - 理解数据流转

### 路径三：学习 eBPF 开发
1. [重点实现的最小模型](./03-minimal-tutorial/README.md) - 动手实践
2. [Q&A: eBPF 挂载说明](./04-qa/README.md) - 深入理解挂载机制

### 路径四：全面掌握
按顺序阅读所有文档：1 → 2 → 3 → 4

---

## 其他资源

- [源码注释](../main.go) - 程序入口，包含完整的组件说明
- [插件系统源码](../internal/plugin/plugin.go) - Plugin 接口和 Manager 实现

---

## 文档维护

本文档库与代码同步维护。如果代码有更新，请同步更新相应文档。

### 文档更新原则
1. 代码修改后，检查相关文档是否需要更新
2. 新增功能时，添加相应的文档说明
3. 保持文档中的代码示例可运行
4. 定期检查和修正过时的内容
