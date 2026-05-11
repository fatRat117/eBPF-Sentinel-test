package main

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ipToString 将32位整数IP地址转换为点分十进制字符串 / Converts a host-order IPv4 integer to dotted decimal.
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}

// protocolToString 将协议号转换为可读字符串 / Converts L4 protocol numbers to labels.
func protocolToString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// getNetworkInterfaces 获取所有活动的网络接口 / Returns active non-loopback interfaces.
func getNetworkInterfaces() []*net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []*net.Interface
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface)
	}
	return result
}

// attachNetworkProgram 挂载网络eBPF程序到指定接口 / Attaches a TCX program to one interface direction.
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

	return link.AttachTCX(link.TCXOptions{
		Interface: ifaceIdx,
		Program:   prog,
		Attach:    attachType,
	})
}
