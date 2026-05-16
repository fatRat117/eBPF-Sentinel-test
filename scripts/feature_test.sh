#!/usr/bin/env bash
#
# eBPF Sentinel scenario test runner.
#
# Purpose:
#   Generate observable system activity for the current Sentinel features:
#   process exec events, process table changes, system metrics, network speed,
#   and alert rules. This is intentionally scenario-based so new plugins can add
#   new run_* functions without rewriting the whole script.
#
# Notes:
#   - Start Sentinel separately, usually with root privileges.
#   - This script does not require root by itself.
#   - Scenarios create real local load. Use conservative duration/size values on
#     small machines.

set -u

API_URL="http://127.0.0.1:8080"
DURATION=20
SCENARIOS="api,execve,sensitive,cpu,memory,network"
YES=0
DRY_RUN=0

CPU_WORKERS=""
MEMORY_MB=""
NETWORK_MB=256
IPERF_HOST=""
IPERF_PORT=5201

RUN_ID="$(date +%Y%m%d-%H%M%S)"
TMP_DIR=""
CHILD_PIDS=()
PASSED=0
FAILED=0
SKIPPED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DIM='\033[2m'
NC='\033[0m'

usage() {
    cat <<EOF
eBPF Sentinel scenario test runner

Usage:
  $0 [options]

Options:
  --api-url URL            Sentinel API base URL. Default: $API_URL
  -s, --scenarios LIST     Comma-separated scenarios. Default: $SCENARIOS
                           Available: api,execve,sensitive,cpu,memory,network,all
  -d, --duration SEC       Duration for load scenarios. Default: $DURATION
  --cpu-workers N          CPU workers. Default: nproc
  --memory-mb MB           Memory pressure size. Default: min(25% MemAvailable, 1024)
  --network-mb MB          Loopback transfer size. Default: $NETWORK_MB
  --iperf-host HOST        Optional iperf3 server for real NIC load
  --iperf-port PORT        iperf3 port. Default: $IPERF_PORT
  -n, --dry-run            Print selected scenarios without running them
  -y, --yes                Skip confirmation
  -h, --help               Show help

Examples:
  $0 --yes
  $0 -s api,execve,sensitive --yes
  $0 -s cpu,memory -d 30 --memory-mb 512 --yes
  $0 -s network --network-mb 1024 --iperf-host 192.168.1.10 --yes
EOF
}

log() {
    printf "${BLUE}[%s]${NC} %s\n" "$(date +%H:%M:%S)" "$*"
}

info() {
    printf "  %s\n" "$*"
}

pass() {
    PASSED=$((PASSED + 1))
    printf "${GREEN}[PASS]${NC} %s\n" "$*"
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    printf "${YELLOW}[SKIP]${NC} %s\n" "$*"
}

fail() {
    FAILED=$((FAILED + 1))
    printf "${RED}[FAIL]${NC} %s\n" "$*"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

is_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

json_count() {
    if has_cmd jq; then
        jq 'if type == "array" then length else 1 end' 2>/dev/null || printf "unknown"
    else
        wc -c | awk '{print $1 " bytes"}'
    fi
}

api_get() {
    curl -fsS --max-time 4 "$API_URL$1"
}

api_status() {
    curl -o /dev/null -sS -w '%{http_code}' --max-time 4 "$API_URL$1"
}

cleanup_children() {
    local pid
    for pid in "${CHILD_PIDS[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    done
    wait >/dev/null 2>&1 || true
    CHILD_PIDS=()
}

cleanup() {
    cleanup_children
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --api-url)
                API_URL="$2"
                shift 2
                ;;
            -s|--scenarios)
                SCENARIOS="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            --cpu-workers)
                CPU_WORKERS="$2"
                shift 2
                ;;
            --memory-mb)
                MEMORY_MB="$2"
                shift 2
                ;;
            --network-mb)
                NETWORK_MB="$2"
                shift 2
                ;;
            --iperf-host)
                IPERF_HOST="$2"
                shift 2
                ;;
            --iperf-port)
                IPERF_PORT="$2"
                shift 2
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -y|--yes)
                YES=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf "${RED}Unknown option:${NC} %s\n\n" "$1"
                usage
                exit 2
                ;;
        esac
    done

    if [ "$SCENARIOS" = "all" ]; then
        SCENARIOS="api,execve,sensitive,cpu,memory,network"
    fi

    if ! is_number "$DURATION" || [ "$DURATION" -lt 1 ]; then
        printf "${RED}--duration must be a positive integer${NC}\n"
        exit 2
    fi
    if ! is_number "$NETWORK_MB" || [ "$NETWORK_MB" -lt 1 ]; then
        printf "${RED}--network-mb must be a positive integer${NC}\n"
        exit 2
    fi
    if [ -n "$CPU_WORKERS" ] && { ! is_number "$CPU_WORKERS" || [ "$CPU_WORKERS" -lt 1 ]; }; then
        printf "${RED}--cpu-workers must be a positive integer${NC}\n"
        exit 2
    fi
    if [ -n "$MEMORY_MB" ] && { ! is_number "$MEMORY_MB" || [ "$MEMORY_MB" -lt 1 ]; }; then
        printf "${RED}--memory-mb must be a positive integer${NC}\n"
        exit 2
    fi
    if ! is_number "$IPERF_PORT" || [ "$IPERF_PORT" -lt 1 ] || [ "$IPERF_PORT" -gt 65535 ]; then
        printf "${RED}--iperf-port must be 1-65535${NC}\n"
        exit 2
    fi
}

scenario_enabled() {
    case ",$SCENARIOS," in
        *,"$1",*) return 0 ;;
        *) return 1 ;;
    esac
}

validate_scenarios() {
    local old_ifs="$IFS"
    local scenario
    IFS=','
    for scenario in $SCENARIOS; do
        case "$scenario" in
            api|execve|sensitive|cpu|memory|network) ;;
            *)
                IFS="$old_ifs"
                printf "${RED}Unknown scenario:${NC} %s\n" "$scenario"
                exit 2
                ;;
        esac
    done
    IFS="$old_ifs"
}

print_plan() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} eBPF Sentinel Scenario Test Runner${NC}"
    echo -e "${BLUE}========================================${NC}"
    info "run id:       $RUN_ID"
    info "api url:      $API_URL"
    info "scenarios:    $SCENARIOS"
    info "duration:     ${DURATION}s"
    info "network size: ${NETWORK_MB}MB"
    if [ -n "$CPU_WORKERS" ]; then
        info "cpu workers:  $CPU_WORKERS"
    else
        info "cpu workers:  auto"
    fi
    if [ -n "$MEMORY_MB" ]; then
        info "memory:       ${MEMORY_MB}MB"
    else
        info "memory:       auto"
    fi
    if [ -n "$IPERF_HOST" ]; then
        info "iperf3:       $IPERF_HOST:$IPERF_PORT"
    fi
    echo ""
}

confirm_plan() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return
    fi
    if [ "$YES" -eq 1 ]; then
        return
    fi

    echo -e "${YELLOW}This will create short-lived CPU, memory, process, and network load.${NC}"
    echo -e "${YELLOW}Start Sentinel in another terminal before continuing.${NC}"
    printf "Continue? [y/N] "
    local answer
    read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) echo "Cancelled"; exit 0 ;;
    esac
}

preflight() {
    if ! has_cmd curl; then
        fail "curl is required for Sentinel API preflight checks"
        exit 1
    fi

    local status
    status="$(api_status /api/policy/status 2>/dev/null || true)"
    if [ "$status" != "200" ]; then
        fail "Sentinel API is not reachable at $API_URL (policy status HTTP $status)"
        info "Start the current build first, for example: sudo ./eBPF-Sentinel"
        exit 1
    fi

    if scenario_enabled sensitive || scenario_enabled cpu || scenario_enabled network; then
        status="$(api_status /api/alerts 2>/dev/null || true)"
        if [ "$status" != "200" ]; then
            fail "Current Sentinel service does not expose /api/alerts (HTTP $status)"
            info "This usually means you are running an old binary. Rebuild it:"
            info "  GOCACHE=/tmp/ebpf-sentinel-go-cache go build -o eBPF-Sentinel ."
            info "Then restart with root privileges and rerun this script."
            exit 1
        fi
    fi
}

show_snapshot() {
    if ! has_cmd curl; then
        skip "curl is missing; cannot collect API snapshot"
        return
    fi

    log "API snapshot"
    local path response
    for path in /api/policy/status /api/events /api/network-events /api/alerts; do
        if response="$(api_get "$path" 2>/dev/null)"; then
            if [ "$path" = "/api/policy/status" ]; then
                info "$path => $response"
            else
                info "$path => $(printf '%s' "$response" | json_count)"
            fi
        else
            info "$path => unavailable"
        fi
    done
}

run_api() {
    log "Scenario api: HTTP endpoints"
    if ! has_cmd curl; then
        skip "curl is missing"
        return
    fi

    local path
    for path in / /assets/app.js /api/policy/status /api/events /api/network-events /api/alerts; do
        if curl -fsS --max-time 4 "$API_URL$path" >/dev/null; then
            pass "endpoint reachable: $path"
        else
            fail "endpoint unreachable: $path"
        fi
    done
}

run_execve() {
    log "Scenario execve: process execution events"
    local i
    for i in $(seq 1 100); do
        /bin/true
        /bin/echo "ebpf-sentinel-$RUN_ID-$i" >/dev/null
        /usr/bin/id >/dev/null 2>&1 || true
        /bin/uname >/dev/null 2>&1 || true
    done
    pass "generated 400-ish exec attempts"
}

run_sensitive() {
    log "Scenario sensitive: alert-sensitive commands"
    TMP_DIR="${TMP_DIR:-$(mktemp -d)}"

    touch "$TMP_DIR/chmod-target"
    chmod 600 "$TMP_DIR/chmod-target"
    chmod 644 "$TMP_DIR/chmod-target"
    pass "executed chmod"

    local cmd
    local executed=0
    for cmd in nc ncat netcat socat tcpdump nmap masscan chattr; do
        if has_cmd "$cmd"; then
            "$cmd" --help >/dev/null 2>&1 || "$cmd" -h >/dev/null 2>&1 || true
            pass "executed $cmd"
            executed=$((executed + 1))
        fi
    done

    if [ "$executed" -eq 0 ]; then
        skip "no optional sensitive command tools found"
    fi
}

run_cpu() {
    log "Scenario cpu: high CPU load"
    local workers="$CPU_WORKERS"
    if [ -z "$workers" ]; then
        workers="$(nproc 2>/dev/null || echo 2)"
    fi

    info "workers=$workers duration=${DURATION}s"
    local i
    for i in $(seq 1 "$workers"); do
        if has_cmd yes; then
            yes >/dev/null &
        else
            sh -c 'while :; do :; done' &
        fi
        CHILD_PIDS+=("$!")
    done

    sleep "$DURATION"
    cleanup_children
    pass "CPU load completed; expect high_cpu_usage alert when system metrics are enabled"
}

default_memory_mb() {
    local available_kb
    available_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if [ "$available_kb" -le 0 ]; then
        echo 256
        return
    fi

    local mb=$((available_kb / 1024 / 4))
    if [ "$mb" -lt 64 ]; then
        mb=64
    fi
    if [ "$mb" -gt 1024 ]; then
        mb=1024
    fi
    echo "$mb"
}

run_memory() {
    log "Scenario memory: process memory pressure"
    if ! has_cmd python3; then
        skip "python3 is missing"
        return
    fi

    local mb="$MEMORY_MB"
    if [ -z "$mb" ]; then
        mb="$(default_memory_mb)"
    fi

    info "allocating=${mb}MB duration=${DURATION}s"
    python3 - "$mb" "$DURATION" <<'PY' &
import sys
import time

mb = int(sys.argv[1])
duration = int(sys.argv[2])
chunks = []
for _ in range(mb):
    block = bytearray(1024 * 1024)
    block[0] = 1
    block[-1] = 1
    chunks.append(block)
time.sleep(duration)
PY
    CHILD_PIDS+=("$!")
    wait "${CHILD_PIDS[-1]}" || true
    CHILD_PIDS=()
    pass "memory pressure completed; inspect process monitor for RSS/MEM movement"
}

run_network_loopback_nc() {
    if ! has_cmd nc; then
        skip "nc is missing; loopback network load skipped"
        return
    fi
    if ! has_cmd dd; then
        skip "dd is missing; loopback network load skipped"
        return
    fi

    local port=$((23000 + RANDOM % 10000))
    info "loopback nc transfer=${NETWORK_MB}MB port=$port"

    nc -l 127.0.0.1 "$port" >/dev/null &
    local server_pid="$!"
    CHILD_PIDS+=("$server_pid")
    sleep 1

    if dd if=/dev/zero bs=1M count="$NETWORK_MB" 2>/dev/null | nc 127.0.0.1 "$port" >/dev/null 2>&1; then
        pass "loopback network transfer completed"
    else
        fail "loopback network transfer failed"
    fi

    wait "$server_pid" >/dev/null 2>&1 || true
    cleanup_children
}

run_network_iperf3() {
    if [ -z "$IPERF_HOST" ]; then
        return
    fi
    if ! has_cmd iperf3; then
        skip "iperf3 is missing"
        return
    fi

    info "iperf3 client target=$IPERF_HOST:$IPERF_PORT duration=${DURATION}s"
    if iperf3 -c "$IPERF_HOST" -p "$IPERF_PORT" -t "$DURATION"; then
        pass "iperf3 network load completed"
    else
        fail "iperf3 network load failed"
    fi
}

run_network() {
    log "Scenario network: throughput and network events"
    run_network_loopback_nc
    run_network_iperf3
    info "expect network events, net speed chart movement, and high_*_speed alerts when thresholds are exceeded"
}

run_selected_scenarios() {
    scenario_enabled api && run_api
    scenario_enabled execve && run_execve
    scenario_enabled sensitive && run_sensitive
    scenario_enabled cpu && run_cpu
    scenario_enabled memory && run_memory
    scenario_enabled network && run_network
}

summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    info "passed:  $PASSED"
    info "failed:  $FAILED"
    info "skipped: $SKIPPED"
    echo -e "${DIM}Review the web UI tabs: 全部事件, 进程监控, 网络事件, 告警中心.${NC}"
}

main() {
    parse_args "$@"
    validate_scenarios
    print_plan

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry run only; no load generated"
        exit 0
    fi

    confirm_plan
    preflight
    show_snapshot
    run_selected_scenarios
    log "waiting 3 seconds for Sentinel to flush tail events"
    sleep 3
    show_snapshot
    summary

    if [ "$FAILED" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
