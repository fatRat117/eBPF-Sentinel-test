package plugin

const (
	ExecveEventSize  = 152
	NetworkEventSize = 38
)

// ExecveEventBinary must match struct event in ebpf/execve.c.
type ExecveEventBinary struct {
	PID   uint32
	PPID  uint32
	Comm  [16]byte
	Argv0 [128]byte
}

// NetworkEventBinary is parsed manually because the C struct contains padding.
type NetworkEventBinary struct {
	PID        uint32
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Direction  uint8
	PacketSize uint32
	Comm       [16]byte
}

// CPUStatBinary must match struct cpu_stat in ebpf/cpu.c.
type CPUStatBinary struct {
	BusyNs uint64
	IdleNs uint64
	LastTs uint64
	IsBusy uint32
	_      [4]byte
}
