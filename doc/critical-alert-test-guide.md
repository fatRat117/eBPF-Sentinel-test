# Critical Alert Test Guide

本文说明告警中心的处理按钮规则，以及几种可以触发 `critical` 告警的测试方式。

## 处理按钮显示规则

告警中心的“终止进程”按钮不是按告警级别决定的。

当前前端显示按钮的条件是：

- 告警状态是 `active`
- 告警详情里能解析出有效的 `pid`

因此：

- `info` / `warning` / `medium` / `critical` 只要带有效 `pid`，并且状态还是 `active`，都可以显示处理按钮。
- 如果告警没有 `pid`，例如纯系统指标类告警，前端不会显示“终止进程”按钮。
- 如果告警已经被标记为 `terminated`、`exited`、`failed`、`resolved` 或 `ignored`，前端不会继续显示重复终止按钮。

## 触发前准备

启动新的 Sentinel 二进制：

```bash
sudo ./eBPF-Sentinel
```

确认策略开关开启：

```bash
curl http://127.0.0.1:8080/api/policy/status
```

查看告警：

```bash
curl http://127.0.0.1:8080/api/alerts
```

如果要看历史告警：

```bash
curl 'http://127.0.0.1:8080/api/alerts?history=true'
```

注意：进程关联告警需要 Sentinel 看到进程启动事件，所以要先启动 Sentinel，再执行测试命令。

## 方法一：本机出站 ncat 触发反弹 Shell 告警

这会触发：

- `rule_id`: `reverse_shell_detected`
- `severity`: `critical`

在另一台机器上监听 4444：

```bash
ncat -lv 4444
```

在运行 Sentinel 的机器上连接过去：

```bash
ncat <另一台机器IP> 4444
```

然后查看告警中心。该方式会产生 `ncat` 执行事件和到可疑端口 `4444` 的网络事件。

## 方法二：被监控机器监听 4444，由另一台机器连接

这也会触发：

- `rule_id`: `reverse_shell_detected`
- `severity`: `critical`

在运行 Sentinel 的机器上监听：

```bash
ncat -lv 4444
```

在另一台机器上连接：

```bash
ncat <Sentinel机器真实网卡IP> 4444
```

不要使用 `127.0.0.1` 或 `localhost` 验证网络侧行为。当前网络 eBPF 挂载到非 loopback 网卡，loopback 流量不适合作为这条链路的验证方式。

## 方法三：进程链攻击告警

这会触发：

- `rule_id`: `process_chain_attack`
- `severity`: `critical`

规则里包含类似 `bash -> python -> sh` 的父子进程链模式。可以用下面命令在本机触发：

```bash
bash -c 'python3 -c "import subprocess; subprocess.run([\"sh\", \"-c\", \"true\"])"'
```

如果系统只有 `python`，可以改成：

```bash
bash -c 'python -c "import subprocess; subprocess.run([\"sh\", \"-c\", \"true\"])"'
```

触发失败时，优先检查进程事件里是否出现了 `bash`、`python` 或 `python3`、`sh`。当前规则已经同时覆盖 `python` 和 `python3`。

## 方法四：疑似数据外泄告警

这会触发：

- `rule_id`: `data_exfil_detected`
- `severity`: `critical`

该规则需要同一个 PID 在短时间内满足：

- 进程事件中命令参数包含敏感路径，例如 `/etc/shadow`
- 随后出现较大的出站网络包，默认阈值为 `1MiB`

这个规则在真实命令行里不一定容易稳定触发，因为当前 execve 采集的是执行文件路径，不一定包含完整参数。更可靠的验证方式是运行单元测试：

```bash
GOCACHE=/tmp/go-build-cache go test ./internal/plugin -run TestDataExfil -v
```

如果要做真实链路测试，建议后续先增强 execve 采集，让它记录完整 argv，而不是只记录 `ctx->args[0]`。

## 推荐优先验证顺序

1. 先用方法一或方法二验证 `reverse_shell_detected`。
2. 再用方法三验证 `process_chain_attack`。
3. `data_exfil_detected` 目前更适合用单元测试证明规则有效。

## 常见失败原因

- Sentinel 启动前就已经运行了 `ncat`，导致没有 execve 事件。
- 使用了 `127.0.0.1` 或 `localhost`，网络事件没有经过非 loopback 网卡。
- 告警处于 cooldown 窗口内，同一个规则和 PID 的重复告警被抑制。
- 告警详情里没有有效 `pid`，所以界面不会显示“终止进程”按钮。
- 前端看到的是历史告警，需要确认 `/api/alerts` 默认只返回本次启动后的告警。
