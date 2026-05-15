package plugin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type networkObjects struct {
	TcEgress             *ebpf.Program `ebpf:"tc_egress"`
	TcIngress            *ebpf.Program `ebpf:"tc_ingress"`
	IpWhitelist          *ebpf.Map     `ebpf:"ip_whitelist"`
	IpWhitelistEnabled   *ebpf.Map     `ebpf:"ip_whitelist_enabled"`
	NetEvents            *ebpf.Map     `ebpf:"net_events"`
	NetMonitoringEnabled *ebpf.Map     `ebpf:"net_monitoring_enabled"`
	PortWhitelist        *ebpf.Map     `ebpf:"port_whitelist"`
	PortWhitelistEnabled *ebpf.Map     `ebpf:"port_whitelist_enabled"`
	SampleCounter        *ebpf.Map     `ebpf:"sample_counter"`
}

func (o *networkObjects) Close() error {
	var err error
	if o.TcEgress != nil {
		err = errors.Join(err, o.TcEgress.Close())
	}
	if o.TcIngress != nil {
		err = errors.Join(err, o.TcIngress.Close())
	}
	if o.IpWhitelist != nil {
		err = errors.Join(err, o.IpWhitelist.Close())
	}
	if o.IpWhitelistEnabled != nil {
		err = errors.Join(err, o.IpWhitelistEnabled.Close())
	}
	if o.NetEvents != nil {
		err = errors.Join(err, o.NetEvents.Close())
	}
	if o.NetMonitoringEnabled != nil {
		err = errors.Join(err, o.NetMonitoringEnabled.Close())
	}
	if o.PortWhitelist != nil {
		err = errors.Join(err, o.PortWhitelist.Close())
	}
	if o.PortWhitelistEnabled != nil {
		err = errors.Join(err, o.PortWhitelistEnabled.Close())
	}
	if o.SampleCounter != nil {
		err = errors.Join(err, o.SampleCounter.Close())
	}
	return err
}

type NetworkPlugin struct {
	BasePlugin
	provider BPFCollectionProvider
	objs     *networkObjects
	reader   *ringbuf.Reader
	enabled  atomic.Bool
}

func NewNetworkPlugin(provider BPFCollectionProvider) *NetworkPlugin {
	p := &NetworkPlugin{
		BasePlugin: BasePlugin{
			Name_:        "network",
			Description_: "Monitor sampled network traffic",
		},
		provider: provider,
	}
	p.enabled.Store(true)
	return p
}

func (p *NetworkPlugin) Load() error {
	if p.provider == nil {
		return errors.New("network BPF provider is nil")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := &networkObjects{}
	if err := p.provider.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load network objects: %w", err)
	}
	p.objs = objs
	if err := p.syncMonitoringMap(p.IsEnabled()); err != nil {
		return err
	}
	log.Printf("[%s] Network monitoring enabled", p.Name())
	return nil
}

func (p *NetworkPlugin) Attach() error {
	if p.objs == nil {
		return nil
	}

	interfaces := activeNetworkInterfaces()
	if len(interfaces) == 0 {
		return errors.New("no active network interfaces found")
	}

	var interfaceNames []string
	for _, iface := range interfaces {
		interfaceNames = append(interfaceNames, iface.Name)
	}
	log.Printf("[%s] Found interfaces: %s", p.Name(), strings.Join(interfaceNames, ", "))

	var attached []string
	for _, iface := range interfaces {
		ingress, err := p.attachProgram(iface.Index, true)
		if err != nil {
			log.Printf("[%s] failed to attach ingress to %s: %v", p.Name(), iface.Name, err)
			continue
		}

		egress, err := p.attachProgram(iface.Index, false)
		if err != nil {
			log.Printf("[%s] failed to attach egress to %s: %v", p.Name(), iface.Name, err)
			ingress.Close()
			continue
		}

		p.Links = append(p.Links, ingress, egress)
		attached = append(attached, iface.Name)
	}
	if len(attached) == 0 {
		return errors.New("failed to attach to any network interface")
	}
	log.Printf("[%s] Network monitoring enabled on: %s", p.Name(), strings.Join(attached, ", "))

	reader, err := ringbuf.NewReader(p.objs.NetEvents)
	if err != nil {
		return fmt.Errorf("open network ring buffer: %w", err)
	}
	p.reader = reader
	return nil
}

func (p *NetworkPlugin) Start(eventChan chan<- *Event) error {
	if p.reader == nil {
		return nil
	}
	for {
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read network ring buffer: %w", err)
		}
		if len(record.RawSample) < NetworkEventSize {
			continue
		}

		raw := parseNetworkEvent(record.RawSample)
		if !p.IsEnabled() {
			continue
		}

		comm := string(bytes.Trim(raw.Comm[:], "\x00"))
		direction := "ingress"
		if raw.Direction == 1 {
			direction = "egress"
		}

		select {
		case eventChan <- &Event{
			Type:      "network",
			Timestamp: time.Now().Unix(),
			Data: map[string]interface{}{
				"pid":          raw.PID,
				"src_ip":       ipToString(raw.SrcIP),
				"dst_ip":       ipToString(raw.DstIP),
				"src_port":     raw.SrcPort,
				"dst_port":     raw.DstPort,
				"protocol":     protocolToString(raw.Protocol),
				"protocol_id":  raw.Protocol,
				"direction":    direction,
				"direction_id": raw.Direction,
				"packet_size":  raw.PacketSize,
				"comm":         comm,
			},
		}:
		default:
			log.Printf("[%s] event channel full, dropping event", p.Name())
		}
	}
}

func (p *NetworkPlugin) Detach() error {
	return p.BasePlugin.Detach()
}

func (p *NetworkPlugin) Close() error {
	var err error
	if p.reader != nil {
		err = errors.Join(err, p.reader.Close())
		p.reader = nil
	}
	err = errors.Join(err, p.Detach())
	if p.objs != nil {
		err = errors.Join(err, p.objs.Close())
		p.objs = nil
	}
	return err
}

func (p *NetworkPlugin) IsEnabled() bool {
	return p.enabled.Load()
}

func (p *NetworkPlugin) SetEnabled(enabled bool) error {
	if err := p.syncMonitoringMap(enabled); err != nil {
		return err
	}
	p.enabled.Store(enabled)
	log.Printf("[%s] Network monitoring enabled: %v", p.Name(), enabled)
	return nil
}

func (p *NetworkPlugin) AddIPWhitelist(ip string) error {
	if p.objs == nil {
		return nil
	}
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return fmt.Errorf("invalid IPv4 address %q", ip)
	}
	key := binary.BigEndian.Uint32(parsed)
	return p.updateWhitelist(p.objs.IpWhitelist, p.objs.IpWhitelistEnabled, key, true)
}

func (p *NetworkPlugin) RemoveIPWhitelist(ip string) error {
	if p.objs == nil {
		return nil
	}
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return fmt.Errorf("invalid IPv4 address %q", ip)
	}
	key := binary.BigEndian.Uint32(parsed)
	return p.deleteWhitelist(p.objs.IpWhitelist, p.objs.IpWhitelistEnabled, key)
}

func (p *NetworkPlugin) AddPortWhitelist(port uint16) error {
	if p.objs == nil {
		return nil
	}
	return p.updateWhitelist(p.objs.PortWhitelist, p.objs.PortWhitelistEnabled, port, true)
}

func (p *NetworkPlugin) RemovePortWhitelist(port uint16) error {
	if p.objs == nil {
		return nil
	}
	return p.deleteWhitelist(p.objs.PortWhitelist, p.objs.PortWhitelistEnabled, port)
}

func (p *NetworkPlugin) syncMonitoringMap(enabled bool) error {
	if p.objs == nil || p.objs.NetMonitoringEnabled == nil {
		return nil
	}
	return updateToggleMap(p.objs.NetMonitoringEnabled, enabled)
}

func (p *NetworkPlugin) attachProgram(ifaceIdx int, ingress bool) (link.Link, error) {
	prog := p.objs.TcEgress
	attachType := ebpf.AttachTCXEgress
	if ingress {
		prog = p.objs.TcIngress
		attachType = ebpf.AttachTCXIngress
	}
	return link.AttachTCX(link.TCXOptions{
		Interface: ifaceIdx,
		Program:   prog,
		Attach:    attachType,
	})
}

func (p *NetworkPlugin) updateWhitelist(target *ebpf.Map, toggle *ebpf.Map, key interface{}, enabled bool) error {
	if target == nil || toggle == nil {
		return nil
	}
	var value uint8 = 1
	if err := target.Update(key, value, ebpf.UpdateAny); err != nil {
		return err
	}
	return updateToggleMap(toggle, enabled)
}

func (p *NetworkPlugin) deleteWhitelist(target *ebpf.Map, toggle *ebpf.Map, key interface{}) error {
	if target == nil || toggle == nil {
		return nil
	}
	if err := target.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return updateToggleMap(toggle, true)
}

func parseNetworkEvent(raw []byte) NetworkEventBinary {
	event := NetworkEventBinary{
		PID:        binary.LittleEndian.Uint32(raw[0:4]),
		SrcIP:      binary.LittleEndian.Uint32(raw[4:8]),
		DstIP:      binary.LittleEndian.Uint32(raw[8:12]),
		SrcPort:    binary.LittleEndian.Uint16(raw[12:14]),
		DstPort:    binary.LittleEndian.Uint16(raw[14:16]),
		Protocol:   raw[16],
		Direction:  raw[17],
		PacketSize: binary.LittleEndian.Uint32(raw[18:22]),
	}
	copy(event.Comm[:], raw[22:38])
	return event
}

func activeNetworkInterfaces() []*net.Interface {
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

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}

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

func updateToggleMap(target *ebpf.Map, enabled bool) error {
	var key uint32
	var value uint32
	if enabled {
		value = 1
	}
	return target.Update(key, value, ebpf.UpdateAny)
}
