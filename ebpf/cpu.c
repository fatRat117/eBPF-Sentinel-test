#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// CPU时间统计结构体
// 每个CPU核心独立维护一份统计
struct cpu_stat {
    u64 busy_ns;    // 非idle进程累计运行时间（纳秒）
    u64 idle_ns;    // idle进程累计运行时间（纳秒）
    u64 last_ts;    // 上次状态切换时间戳（纳秒）
    u32 is_busy;    // 当前是否处于busy状态：1=busy, 0=idle
};

// PERCPU数组Map - 每个CPU核心独立存储cpu_stat
// 通过BPF_MAP_TYPE_PERCPU_ARRAY实现无锁访问
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_stat);
} cpu_stats SEC(".maps");

/**
 * @brief 调度切换tracepoint处理函数
 * 
 * 挂载到sched/sched_switch跟踪点，在每次进程切换时计算
 * 上一个任务在CPU上运行的时间，并根据其是否为idle进程
 * 累加到busy_ns或idle_ns。
 * 
 * idle进程的pid为0（swapper进程）。
 * 
 * @param ctx tracepoint上下文
 * @return 0 表示成功
 */
SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u32 key = 0;
    struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &key);
    if (!stat)
        return 0;

    u64 now = bpf_ktime_get_ns();

    // 计算从last_ts到现在的时间差，累加到对应的状态
    if (stat->last_ts > 0) {
        u64 delta = now - stat->last_ts;
        if (stat->is_busy) {
            stat->busy_ns += delta;
        } else {
            stat->idle_ns += delta;
        }
    }

    // 更新当前状态：next_pid == 0 表示下一个任务是idle
    stat->is_busy = (ctx->next_pid != 0) ? 1 : 0;
    stat->last_ts = now;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
