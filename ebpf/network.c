#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// 网络协议常量定义
#define ETH_P_IP 0x0800      // IPv4以太网协议类型
#define ETH_HLEN 14          // 以太网头部长度
#define IP_PROTO_TCP 6       // TCP协议号
#define IP_PROTO_UDP 17      // UDP协议号
#define IP_PROTO_ICMP 1      // ICMP协议号

// 采样配置 - 每N个包采样1个
// 设置为100表示每100个包采样1个，既能减少事件量又能保证检测到流量
#define SAMPLE_RATE 100

// 网络事件结构体 - 用于向用户态传递网络数据包信息
struct net_event {
    u32 pid;                 // 产生/接收此数据包的进程ID
    u32 src_ip;             // 源IP地址（网络字节序转换后）
    u32 dst_ip;             // 目的IP地址（网络字节序转换后）
    u16 src_port;           // 源端口
    u16 dst_port;           // 目的端口
    u8 protocol;            // 传输层协议（TCP/UDP/ICMP）
    u8 direction;           // 方向：0=入站(ingress), 1=出站(egress)
    u32 packet_size;        // 数据包大小（字节）
    char comm[16];          // 进程名
};

// Ring Buffer Map - 用于将网络事件从内核态异步发送到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// 采样计数器 - 每个CPU核心独立的计数器
// key: 0=ingress, 1=egress
// value: 该方向的包计数
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} sample_counter SEC(".maps");

// IP白名单Map - 存储允许监控的IP地址
// 如果设置了白名单，只有白名单中的IP才会被监控
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);   // IP地址
    __type(value, u8);  // 1表示在白名单中
} ip_whitelist SEC(".maps");

// 端口白名单Map - 存储允许监控的端口
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u16);   // 端口号
    __type(value, u8);  // 1表示在白名单中
} port_whitelist SEC(".maps");

// 全局开关 - 控制网络监控是否启用
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} net_monitoring_enabled SEC(".maps");

/**
 * @brief 从IP头部解析协议号
 * @param data IP数据包起始位置
 * @param data_end 数据包结束位置（用于边界检查）
 * @return 协议号，如果解析失败返回0
 */
static __always_inline u8 get_ip_protocol(void *data, void *data_end) {
    struct iphdr *ip = data;
    // 边界检查：确保不会访问超出数据包范围的数据
    if ((void *)(ip + 1) > data_end)
        return 0;
    return ip->protocol;
}

/**
 * @brief 从IP头部解析源IP地址
 * @param data IP数据包起始位置
 * @param data_end 数据包结束位置
 * @return 源IP地址（主机字节序），如果解析失败返回0
 */
static __always_inline u32 get_src_ip(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 0;
    // bpf_ntohl将网络字节序转换为主机字节序
    return bpf_ntohl(ip->saddr);
}

/**
 * @brief 从IP头部解析目的IP地址
 * @param data IP数据包起始位置
 * @param data_end 数据包结束位置
 * @return 目的IP地址（主机字节序），如果解析失败返回0
 */
static __always_inline u32 get_dst_ip(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 0;
    return bpf_ntohl(ip->daddr);
}

/**
 * @brief 从传输层头部解析源端口
 * @param data 传输层数据起始位置
 * @param data_end 数据包结束位置
 * @param protocol 传输层协议类型
 * @return 源端口号（主机字节序），如果解析失败返回0
 */
static __always_inline u16 get_src_port(void *data, void *data_end, u8 protocol) {
    if (protocol == IP_PROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->source);
    } else if (protocol == IP_PROTO_UDP) {
        struct udphdr *udp = data;
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->source);
    }
    return 0;
}

/**
 * @brief 从传输层头部解析目的端口
 * @param data 传输层数据起始位置
 * @param data_end 数据包结束位置
 * @param protocol 传输层协议类型
 * @return 目的端口号（主机字节序），如果解析失败返回0
 */
static __always_inline u16 get_dst_port(void *data, void *data_end, u8 protocol) {
    if (protocol == IP_PROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->dest);
    } else if (protocol == IP_PROTO_UDP) {
        struct udphdr *udp = data;
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->dest);
    }
    return 0;
}

/**
 * @brief 检查是否应该采样此数据包
 * 
 * 使用简单的计数器采样策略，每SAMPLE_RATE个包采样1个。
 * 这样可以减少高流量环境下的性能开销。
 * 
 * @param direction 数据包方向（0=ingress, 1=egress）
 * @return true 如果应该采样此数据包
 */
static __always_inline bool should_sample(u32 direction) {
    u32 key = direction;
    u64 *counter = bpf_map_lookup_elem(&sample_counter, &key);
    
    u64 new_val = 1;
    if (counter) {
        new_val = *counter + 1;
    }
    
    bpf_map_update_elem(&sample_counter, &key, &new_val, BPF_ANY);
    
    return (new_val % SAMPLE_RATE) == 0;
}

/**
 * @brief 检查IP地址是否在白名单中
 * @param ip IP地址（主机字节序）
 * @return true 如果在白名单中或白名单为空
 */
static __always_inline bool is_ip_whitelisted(u32 ip) {
    // 如果白名单为空，允许所有IP
    u8 *value = bpf_map_lookup_elem(&ip_whitelist, &ip);
    return value == NULL || *value == 1;
}

/**
 * @brief 检查端口是否在白名单中
 * @param port 端口号
 * @return true 如果在白名单中或白名单为空
 */
static __always_inline bool is_port_whitelisted(u16 port) {
    u8 *value = bpf_map_lookup_elem(&port_whitelist, &port);
    return value == NULL || *value == 1;
}

/**
 * @brief 检查网络监控是否启用
 * @return true 如果监控启用
 */
static __always_inline bool is_net_monitoring_enabled() {
    u32 key = 0;
    u32 *value = bpf_map_lookup_elem(&net_monitoring_enabled, &key);
    return value == NULL || *value == 1;
}

/**
 * @brief 处理网络数据包
 * 
 * 这是核心的数据包处理函数，解析以太网、IP和传输层头部，
 * 提取关键信息并通过Ring Buffer发送到用户态。
 * 
 * @param skb Socket Buffer，包含数据包数据
 * @param direction 数据包方向（0=ingress, 1=egress）
 * @return 0 表示成功
 */
static __always_inline int process_packet(struct __sk_buff *skb, u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 检查监控是否启用
    if (!is_net_monitoring_enabled()) {
        return 0;
    }
    
    // 解析以太网头部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    // 只处理IPv4数据包
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;
    
    // IP数据起始位置（跳过以太网头部）
    void *ip_data = data + ETH_HLEN;
    
    // 获取传输层协议
    u8 protocol = get_ip_protocol(ip_data, data_end);
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP && protocol != IP_PROTO_ICMP)
        return 0;
    
    // 采样检查 - 只处理每N个包中的1个
    if (!should_sample(direction)) {
        return 0;
    }
    
    // 获取IP地址
    u32 src_ip = get_src_ip(ip_data, data_end);
    u32 dst_ip = get_dst_ip(ip_data, data_end);
    
    // 白名单检查
    if (!is_ip_whitelisted(src_ip) || !is_ip_whitelisted(dst_ip)) {
        return 0;
    }
    
    // 获取传输层数据起始位置
    struct iphdr *ip = ip_data;
    u8 ip_header_len = ip->ihl * 4;  // IP头部长度（单位：4字节）
    void *transport_data = ip_data + ip_header_len;
    
    // 获取端口信息
    u16 src_port = get_src_port(transport_data, data_end, protocol);
    u16 dst_port = get_dst_port(transport_data, data_end, protocol);
    
    // 端口白名单检查
    if (!is_port_whitelisted(src_port) || !is_port_whitelisted(dst_port)) {
        return 0;
    }
    
    // 在Ring Buffer中预留空间
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // 填充事件数据
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->protocol = protocol;
    e->direction = direction;
    e->packet_size = skb->len;
    e->src_port = src_port;
    e->dst_port = dst_port;
    
    // 获取当前进程名
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 提交事件
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/**
 * @brief TC Ingress程序 - 处理入站流量
 * 
 * 挂载到网络接口的入站路径，处理所有进入系统的数据包。
 * 
 * @param skb Socket Buffer
 * @return 0 表示放行数据包（不拦截）
 */
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    process_packet(skb, 0);
    return 0;
}

/**
 * @brief TC Egress程序 - 处理出站流量
 * 
 * 挂载到网络接口的出站路径，处理所有离开系统的数据包。
 * 
 * @param skb Socket Buffer
 * @return 0 表示放行数据包（不拦截）
 */
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    process_packet(skb, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
