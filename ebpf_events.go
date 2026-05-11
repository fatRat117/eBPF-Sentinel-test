package main

const (
	execveEventSize  = 152
	networkEventSize = 38
)

// execveEvent 对应eBPF中的execve事件结构体 / Must match struct event in ebpf/execve.c.
type execveEvent struct {
	PID   uint32    // 进程ID / Process ID
	PPID  uint32    // 父进程ID / Parent process ID
	Comm  [16]byte  // 进程名 / Command name
	Argv0 [128]byte // 命令行参数 / First argv value
}

// networkEvent 对应eBPF中的网络事件结构体 / Must match struct net_event in ebpf/network.c.
type networkEvent struct {
	PID        uint32   // 进程ID / Process ID
	SrcIP      uint32   // 源IP地址 / Source IPv4 address
	DstIP      uint32   // 目的IP地址 / Destination IPv4 address
	SrcPort    uint16   // 源端口 / Source port
	DstPort    uint16   // 目的端口 / Destination port
	Protocol   uint8    // 传输层协议 / L4 protocol
	Direction  uint8    // 方向：0=入站, 1=出站 / 0=ingress, 1=egress
	PacketSize uint32   // 数据包大小 / Packet size
	Comm       [16]byte // 进程名 / Command name
}
