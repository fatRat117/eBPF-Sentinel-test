# eBPF-Sentinel

**Linux system monitor using eBPF for execve, network, and CPU events**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue)](go.mod)
[![eBPF](https://img.shields.io/badge/eBPF-enabled-green)](https://ebpf.io)

eBPF-Sentinel is a lightweight Linux system monitoring tool that uses eBPF (Extended Berkeley Packet Filter) to trace system events with minimal overhead. It provides real-time monitoring of process execution, network traffic, and CPU usage through a web-based dashboard.

## Features

- **Process Monitoring**: Trace `execve` system calls with process details (PID, PPID, command line)
- **Network Monitoring**: Capture TCP/UDP/ICMP packets with source/destination IPs and ports
- **CPU Monitoring**: Real-time CPU usage statistics via eBPF tracepoints (no external dependencies)
- **Real-time Dashboard**: Single-page web interface with live updates via WebSocket
- **Plugin Architecture**: Extensible plugin system for adding new monitoring capabilities
- **SQLite Storage**: Persistent event storage with GORM ORM
- **Low Overhead**: eBPF-based monitoring with minimal performance impact

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (HTML/JS)                  │
│                    Real-time updates via WebSocket          │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Go HTTP Server (Gin)                     │
│                    - REST API for historical data           │
│                    - WebSocket hub for live events          │
│                    - Static file serving                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Plugin System                            │
│                    - Execve monitoring plugin               │
│                    - Network monitoring plugin              │
│                    - System/CPU monitoring plugin           │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    eBPF Runtime (cilium/ebpf)               │
│                    - Load eBPF programs into kernel         │
│                    - Read events from ring buffers          │
│                    - Manage eBPF maps                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Linux Kernel                             │
│                    - execve tracepoints                     │
│                    - TC network hook points                 │
│                    - sched_switch tracepoints (CPU)        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Linux kernel 5.8+ (for BPF ring buffers and TCX support)
- Go 1.25+
- GCC toolchain for eBPF compilation
- Root privileges (for loading eBPF programs)

### Installation

```bash
# Clone the repository
git clone https://github.com/fatRat117/eBPF-Sentinel.git
cd eBPF-Sentinel

# Build the binary
go build .

# Run with sudo (eBPF requires root)
sudo ./ebpf-sentinel
```

### Usage

1. Start the server:
   ```bash
   sudo ./ebpf-sentinel
   ```

2. Open your browser to `http://localhost:8080`

3. The dashboard will show:
   - Real-time process execution events
   - Network traffic with auto-formatted packet sizes (B/KB/MB)
   - CPU usage statistics
   - System resource utilization

4. Use the API:
   ```bash
   # Get recent process events
   curl http://localhost:8080/api/events/execve

   # Get recent network events  
   curl http://localhost:8080/api/events/network

   # Get system stats
   curl http://localhost:8080/api/stats/system
   ```

## Project Structure

```
.
├── main.go                     # Entry point: loads eBPF, starts server
├── go.mod                      # Go module dependencies
├── ebpf/                       # eBPF C programs
│   ├── execve.c               # Process execution monitoring
│   ├── network.c              # Network packet monitoring
│   ├── cpu.c                  # CPU usage monitoring (new)
│   └── vmlinux.h              # Kernel definitions
├── internal/
│   ├── plugin/                # Plugin interface and implementations
│   ├── models/                # GORM models for SQLite
│   └── websocket/             # WebSocket hub for real-time events
├── web/dist/                  # Single-page dashboard (no build step)
├── scripts/                   # Load testing and utilities
└── doc/                       # Comprehensive documentation
```

## eBPF Programs

### execve.c
- **Hook**: `tracepoint/syscalls/sys_enter_execve`
- **Purpose**: Trace process execution
- **Features**: Whitelist filtering, command line capture

### network.c  
- **Hook**: `TCX` (Traffic Control eXpress) on all interfaces
- **Purpose**: Monitor network traffic
- **Features**: Protocol detection, direction classification

### cpu.c
- **Hook**: `tracepoint/sched/sched_switch`
- **Purpose**: Calculate CPU usage per core
- **Features**: PERCPU maps for zero-contention statistics

## Configuration

### Network Interface Selection
The network monitor automatically attaches to all available interfaces. If you want to exclude specific interfaces, modify `main.go`:

```go
// In main.go, filter interfaces
if strings.HasPrefix(iface.Name, "lo") || strings.HasPrefix(iface.Name, "docker") {
    continue
}
```

### CPU Monitoring
CPU monitoring uses eBPF tracepoints by default. If eBPF fails to load, the system falls back to gopsutil (though this requires the gopsutil dependency).

### Database
Events are stored in `sentinel.db` (SQLite). This file is not committed to git.

## Development

### Adding a New eBPF Program

1. Create a new `.c` file in `ebpf/` directory
2. Define eBPF maps and programs
3. Update `main.go` to load the new program
4. Generate Go bindings:
   ```bash
   go generate ./...
   ```
5. Create or update a plugin in `internal/plugin/`

### Regenerating eBPF Bindings
After modifying `.c` files, regenerate the Go bindings:

```bash
go generate ./...
```

Or manually with bpf2go:
```bash
go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang-19 cpu ./ebpf/cpu.c
```

### Load Testing
Use the included stress test script:

```bash
./scripts/stress_test.sh -d 30 -p 50
```

## Known Issues

### dae Proxy Conflict
eBPF-Sentinel's network monitoring attaches to TC hooks, which may conflict with other eBPF-based networking tools like dae. If you experience network connectivity issues:

1. **Option 1**: Disable eBPF-Sentinel's network monitoring by commenting out the network plugin initialization in `main.go`
2. **Option 2**: Configure dae to use a different interface or adjust its eBPF attachment priority (if supported)

### Permission Requirements
Loading eBPF programs requires root privileges. The program attempts to remove memlock limits automatically.

### Kernel Compatibility
Requires kernel 5.8+ for ring buffer support. Older kernels may need to use perf buffers.

## Documentation

Comprehensive documentation is available in the `doc/` directory:

- `01-project-structure/` - Detailed file-by-file explanation
- `02-architecture-layers/` - System architecture and data flow
- `03-minimal-tutorial/` - Step-by-step eBPF development tutorial
- `04-qa/` - Frequently asked questions

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) - Excellent Go eBPF library
- [gin-gonic/gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [gorm.io/gorm](https://gorm.io) - ORM library for Go

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request