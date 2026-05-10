# eBPF-Sentinel

**Generated:** 2026-04-14  
**Commit:** 9eec629  
**Branch:** master

## OVERVIEW
Linux system monitor using eBPF for execve/network events, with a Go HTTP/WebSocket API and SQLite persistence. Single-page dashboard served from `web/dist/`.

## STRUCTURE
```
.
├── main.go                     # Entry: loads eBPF, starts Gin server on :8080
├── go.mod                      # Go 1.25; deps: cilium/ebpf, gin, gorilla/websocket, gorm/sqlite
├── ebpf/                       # C eBPF programs (execve.c, network.c, vmlinux.h)
├── internal/
│   ├── plugin/                 # Plugin interface + system monitor (no eBPF)
│   ├── models/                 # GORM models + SQLite DB init (sentinel.db)
│   └── websocket/              # Hub + Client pumps for real-time events
├── web/dist/                   # Single-file dashboard (index.html)
├── scripts/                    # stress_test.sh for load testing
└── doc/                        # Human docs (project structure, architecture, Q&A)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add eBPF program | `ebpf/*.c` | Then regenerate `_bpfel.go`/`_bpfel.o` with bpf2go |
| Add API endpoint | `main.go` | `setupRoutes()` registers all Gin routes |
| Change DB schema | `internal/models/event.go` | GORM auto-migrate on startup |
| Add plugin type | `internal/plugin/plugin.go` | Implement `Plugin` interface |
| WebSocket broadcast | `internal/websocket/hub.go` | `Hub.Broadcast()` is the entry |
| Frontend UI | `web/dist/index.html` | Vanilla HTML/CSS/JS, no build step |

## CODE MAP
| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `main` | Func | `main.go:326` | Loads eBPF, starts DB, Gin, WS hub |
| `setupRoutes` | Func | `main.go:136` | API + WS + static file routes |
| `Plugin` | Interface | `internal/plugin/plugin.go:17` | All eBPF plugins implement this |
| `Manager` | Struct | `internal/plugin/plugin.go:79` | Lifecycle manager for plugins |
| `Hub` | Struct | `internal/websocket/hub.go:14` | Manages WS client registry + broadcast |
| `ExecveEvent` | Struct | `internal/models/event.go:12` | GORM model for process events |
| `NetworkEvent` | Struct | `internal/models/event.go:23` | GORM model for network events |

## CONVENTIONS
- Go code comments are bilingual (Chinese + English). Match this style.
- eBPF struct field comments must stay synchronized with Go structs in `main.go`.
- Log prefixes use brackets: `[execve]`, `[network]`, `[system]`, `[WebSocket]`.
- Ring buffer reads use `unsafe`/`binary.LittleEndian` for zero-copy parsing.
- TCX (`link.AttachTCX`) is used for network eBPF attachment instead of legacy `tc`.

## ANTI-PATTERNS (THIS PROJECT)
- Do not add frontend build tools; dashboard is intentionally a single static HTML file.
- Do not use `as any` or `@ts-ignore` (not applicable here, but enforced).
- Do not change `web/dist/index.html` into a framework app.
- Never commit `sentinel.db` (it is a runtime SQLite file).

## COMMANDS
```bash
# Run (requires root for eBPF)
go run .
sudo ./ebpf-sentinel

# Load test
./scripts/stress_test.sh -d 30 -p 50

# Regenerate eBPF Go bindings (after changing .c files)
go generate ./...
# or manually with bpf2go
```

## NOTES
- Generated files (`*_bpfel.go`, `*_bpfel.o`) are checked in and must be kept in sync with `ebpf/*.c`.
- Network monitoring gracefully degrades if no interfaces are attachable.
- WebSocket `upgrader.CheckOrigin` allows all origins (development only).
- `rlimit.RemoveMemlock()` is required before loading eBPF objects.
