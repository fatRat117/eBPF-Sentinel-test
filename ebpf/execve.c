#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_ARGV_LEN 128
#define MAX_TARGETLIST_SIZE 256

// 事件结构体 - 用于向用户态传递进程执行信息
struct event {
    u32 pid;                    // 进程ID
    u32 ppid;                   // 父进程ID
    char comm[TASK_COMM_LEN];   // 进程名
    char argv0[MAX_ARGV_LEN];   // 执行的命令
};

// Ring Buffer Map - 用于将事件从内核态异步发送到用户态
// 256KB的缓冲区可以存储大量事件，减少丢包率
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");



// 全局开关 - 控制是否启用监控
// 0 = 禁用, 1 = 启用
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} monitoring_enabled SEC(".maps");

/**
 * @brief 检查监控是否启用
 * @return true 如果监控启用，false 否则
 */
static __always_inline bool is_monitoring_enabled() {
    u32 key = 0;
    u32 *value = bpf_map_lookup_elem(&monitoring_enabled, &key);
    // 默认为启用状态（如果Map未初始化）
    return value == NULL || *value == 1;
}

/**
 * @brief execve系统调用入口点的跟踪处理函数
 * 
 * 此函数在每次进程调用execve时被触发，收集进程信息并通过Ring Buffer
 * 发送到用户态。支持目标列表过滤和全局开关控制。
 * 
 * @param ctx 跟踪点上下文，包含系统调用参数
 * @return 0 表示成功
 */
SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    const char *filename;
    
    // 检查监控是否启用
    if (!is_monitoring_enabled()) {
        return 0;
    }
    
    // 在Ring Buffer中预留空间用于存储事件
    // 如果缓冲区已满，返回NULL，此时直接返回不处理
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // 获取当前任务的task_struct指针
    task = (struct task_struct *)bpf_get_current_task();
    
    // 获取当前进程的PID（低32位）
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    // 安全地读取父进程信息
    // 使用bpf_probe_read_kernel从内核空间读取数据
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
    
    // 获取当前进程名
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 从tracepoint上下文中读取执行的文件名（第一个参数）
    filename = (const char *)ctx->args[0];
    // 从用户空间安全地读取字符串
    bpf_probe_read_user_str(&e->argv0, sizeof(e->argv0), filename);
    
    // 提交事件到Ring Buffer，用户态程序可以读取
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 许可证声明 - GPL许可证允许使用更多内核功能
char LICENSE[] SEC("license") = "GPL";
