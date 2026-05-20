#!/usr/bin/env bash
# eBPF Sentinel pressure test.
#
# This script intentionally avoids `yes`-style CPU loops. CPU pressure is
# produced by repeatedly compiling generated Go code; memory pressure is
# produced by a bounded allocator that touches pages and releases them on exit.

set -Eeuo pipefail

DURATION=60
MODE="all"
CPU_JOBS="$(nproc 2>/dev/null || echo 2)"
GO_FUNCS=2500
MEM_PERCENT=85
MEM_MB=""
SENTINEL_URL="http://127.0.0.1:8080"
CONFIGURE_ALERTS=1
RESTORE_CONFIG=1
LOCAL_TRAFFIC=1
SUSPICIOUS_NETWORK=1
NETWORK_TARGET="1.1.1.1"
SUSPICIOUS_PORT=4444
ASSUME_YES=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WORKDIR=""
ORIGINAL_ALERT_CONFIG=""
CONFIG_CHANGED=0
PIDS=()

usage() {
    echo -e "${BLUE}eBPF Sentinel 压力测试脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "模式:"
    echo "  -m, --mode MODE              all|cpu|memory|alerts，默认: all"
    echo ""
    echo "通用:"
    echo "  -d, --duration SECONDS       持续时间，默认: 60"
    echo "  -y, --yes                    不交互确认，直接运行"
    echo "  -h, --help                   显示帮助"
    echo ""
    echo "CPU 编译压力:"
    echo "  -j, --cpu-jobs N             并行编译 worker 数，默认: nproc"
    echo "  --go-funcs N                 每个临时包生成的函数数量，默认: 2500"
    echo ""
    echo "内存压力:"
    echo "  --mem-percent N              目标内存使用率，默认: 85"
    echo "  --mem-mb N                   直接指定要分配的内存 MB，优先于 --mem-percent"
    echo ""
    echo "告警触发:"
    echo "  --sentinel-url URL           Sentinel 地址，默认: http://127.0.0.1:8080"
    echo "  --no-alert-config            不临时调低告警阈值"
    echo "  --no-restore-config          退出时不恢复原告警配置"
    echo "  --no-local-traffic           不通过本机 HTTP 流量触发网速告警"
    echo "  --no-suspicious-network      不尝试访问可疑端口"
    echo "  --network-target HOST        可疑端口连接目标，默认: 1.1.1.1"
    echo "  --suspicious-port PORT       可疑端口，默认: 4444"
    echo ""
    echo "示例:"
    echo "  $0 -d 90 -j 8 --mem-percent 90 -y"
    echo "  $0 --mode cpu -d 120 -j 12"
    echo "  $0 --mode memory --mem-mb 4096 -y"
    echo "  $0 --mode alerts --sentinel-url http://127.0.0.1:8080 -y"
}

log() {
    echo -e "$*"
}

die() {
    log "${RED}错误: $*${NC}" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

validate_int() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ] || die "$name 必须是正整数"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -m|--mode)
                MODE="$2"
                shift 2
                ;;
            -j|--cpu-jobs)
                CPU_JOBS="$2"
                shift 2
                ;;
            --go-funcs)
                GO_FUNCS="$2"
                shift 2
                ;;
            --mem-percent)
                MEM_PERCENT="$2"
                shift 2
                ;;
            --mem-mb)
                MEM_MB="$2"
                shift 2
                ;;
            --sentinel-url)
                SENTINEL_URL="${2%/}"
                shift 2
                ;;
            --no-alert-config)
                CONFIGURE_ALERTS=0
                shift
                ;;
            --no-restore-config)
                RESTORE_CONFIG=0
                shift
                ;;
            --no-local-traffic)
                LOCAL_TRAFFIC=0
                shift
                ;;
            --no-suspicious-network)
                SUSPICIOUS_NETWORK=0
                shift
                ;;
            --network-target)
                NETWORK_TARGET="$2"
                shift 2
                ;;
            --suspicious-port)
                SUSPICIOUS_PORT="$2"
                shift 2
                ;;
            -y|--yes)
                ASSUME_YES=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "未知选项: $1"
                ;;
        esac
    done

    case "$MODE" in
        all|cpu|memory|alerts) ;;
        *) die "mode 必须是 all|cpu|memory|alerts" ;;
    esac

    validate_int "duration" "$DURATION"
    validate_int "cpu-jobs" "$CPU_JOBS"
    validate_int "go-funcs" "$GO_FUNCS"
    validate_int "mem-percent" "$MEM_PERCENT"
    validate_int "suspicious-port" "$SUSPICIOUS_PORT"
    if [ -n "$MEM_MB" ]; then
        validate_int "mem-mb" "$MEM_MB"
    fi
}

auth_args() {
    if [ -n "${SENTINEL_ADMIN_TOKEN:-}" ]; then
        printf '%s\n' "-H" "Authorization: Bearer ${SENTINEL_ADMIN_TOKEN}"
    fi
}

curl_sentinel() {
    local args=()
    while IFS= read -r item; do
        args+=("$item")
    done < <(auth_args)
    curl -fsS "${args[@]}" "$@"
}

configure_alerts() {
    [ "$CONFIGURE_ALERTS" -eq 1 ] || return 0
    have_cmd curl || {
        log "${YELLOW}[alerts] curl 不存在，跳过告警配置${NC}"
        return 0
    }
    have_cmd python3 || {
        log "${YELLOW}[alerts] python3 不存在，跳过告警配置${NC}"
        return 0
    }

    if ! ORIGINAL_ALERT_CONFIG="$(curl_sentinel "${SENTINEL_URL}/api/alert/config" 2>/dev/null)"; then
        log "${YELLOW}[alerts] 无法连接 Sentinel API，跳过阈值调整${NC}"
        return 0
    fi

    local payload
    payload="$(python3 - "$ORIGINAL_ALERT_CONFIG" <<'PY'
import json
import sys

cfg = json.loads(sys.argv[1])
cfg.update({
    "cpu_threshold": 20,
    "memory_threshold": 50,
    "net_speed_threshold_kb": 32,
    "packet_size_limit": 512,
    "cooldown_seconds": 3,
    "single_metric_alerts_enabled": True,
})
cfg.setdefault("correlation_window_seconds", 60)
cfg.setdefault("max_time_gap_seconds", 60)
cfg.setdefault("exfil_size_threshold_bytes", 1048576)
print(json.dumps(cfg, separators=(",", ":")))
PY
)"

    if curl_sentinel -X POST "${SENTINEL_URL}/api/alert/config" \
        -H 'Content-Type: application/json' \
        -d "$payload" >/dev/null 2>&1; then
        CONFIG_CHANGED=1
        log "${GREEN}[alerts] 已临时降低告警阈值并启用单指标告警${NC}"
    else
        log "${YELLOW}[alerts] 调整告警阈值失败，继续执行压力测试${NC}"
    fi
}

restore_alert_config() {
    [ "$CONFIG_CHANGED" -eq 1 ] || return 0
    [ "$RESTORE_CONFIG" -eq 1 ] || return 0
    [ -n "$ORIGINAL_ALERT_CONFIG" ] || return 0

    if curl_sentinel -X POST "${SENTINEL_URL}/api/alert/config" \
        -H 'Content-Type: application/json' \
        -d "$ORIGINAL_ALERT_CONFIG" >/dev/null 2>&1; then
        log "${GREEN}[cleanup] 已恢复原告警配置${NC}"
    else
        log "${YELLOW}[cleanup] 恢复告警配置失败，请手动检查设置页${NC}"
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM

    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    done
    for pid in "${PIDS[@]:-}"; do
        wait "$pid" >/dev/null 2>&1 || true
    done

    restore_alert_config || true

    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi

    if [ "$status" -eq 130 ]; then
        log "${YELLOW}测试被用户中断${NC}"
    fi
    exit "$status"
}

generate_go_project() {
    local dir="$1"
    local worker="$2"
    mkdir -p "$dir/stresspkg"

    cat > "$dir/go.mod" <<EOF
module sentinel-stress-${worker}

go 1.20
EOF

    cat > "$dir/stresspkg/stress.go" <<'EOF'
package stresspkg

type Payload struct {
    A0 int
    A1 int
    A2 int
    A3 int
    A4 int
    A5 int
    A6 int
    A7 int
}

EOF

    local i
    for ((i=0; i<GO_FUNCS; i++)); do
        cat >> "$dir/stresspkg/stress.go" <<EOF
func F${i}(x int) int {
    p := Payload{x, x + ${i}, x * 3, x ^ ${i}, x | ${i}, x & 255, x << 1, x >> 1}
    return p.A0 + p.A1 + p.A2 + p.A3 + p.A4 + p.A5 + p.A6 + p.A7
}

EOF
    done

    cat > "$dir/stresspkg/stress_test.go" <<'EOF'
package stresspkg

import "testing"

func TestCompileOnly(t *testing.T) {
    if F0(1) == 0 {
        t.Fatal("unreachable")
    }
}
EOF
}

start_compile_pressure() {
    have_cmd go || die "CPU 编译压力需要 go 命令"

    log "${GREEN}[cpu] 启动 ${CPU_JOBS} 个并行编译 worker${NC}"
    local worker
    for ((worker=1; worker<=CPU_JOBS; worker++)); do
        local dir="${WORKDIR}/compile-${worker}"
        generate_go_project "$dir" "$worker"
        (
            cd "$dir"
            local end_ts=$((SECONDS + DURATION))
            local iter=0
            while [ "$SECONDS" -lt "$end_ts" ]; do
                printf 'package stresspkg\nconst BuildStamp = "%s"\n' "${worker}-${iter}-${RANDOM}" > stresspkg/stamp.go
                GOCACHE="${dir}/gocache" GOMAXPROCS=1 go clean -cache >/dev/null 2>&1 || true
                GOCACHE="${dir}/gocache" GOMAXPROCS=1 go test -run '^$' ./... >/dev/null 2>&1 || true
                iter=$((iter + 1))
            done
        ) &
        PIDS+=("$!")
    done
}

calculate_memory_mb() {
    if [ -n "$MEM_MB" ]; then
        echo "$MEM_MB"
        return
    fi

    awk -v pct="$MEM_PERCENT" '
        /^MemTotal:/ { total=$2/1024 }
        /^MemAvailable:/ { avail=$2/1024 }
        END {
            used = total - avail
            target_used = total * pct / 100
            alloc = target_used - used
            if (alloc < 128) alloc = 128
            printf "%d\n", alloc
        }
    ' /proc/meminfo
}

start_memory_pressure() {
    have_cmd python3 || die "内存压力需要 python3"

    local alloc_mb
    alloc_mb="$(calculate_memory_mb)"
    validate_int "calculated memory MB" "$alloc_mb"

    log "${GREEN}[memory] 目标分配 ${alloc_mb} MB，分块触碰页面并保持 ${DURATION} 秒${NC}"
    python3 - "$alloc_mb" "$DURATION" <<'PY' &
import os
import sys
import time

target_mb = int(sys.argv[1])
duration = int(sys.argv[2])
chunk_mb = 64
blocks = []
allocated = 0

try:
    while allocated < target_mb:
        size_mb = min(chunk_mb, target_mb - allocated)
        block = bytearray(size_mb * 1024 * 1024)
        for i in range(0, len(block), 4096):
            block[i] = 1
        blocks.append(block)
        allocated += size_mb
        print(f"[memory] allocated {allocated}/{target_mb} MB", flush=True)
        time.sleep(0.05)

    end = time.time() + duration
    while time.time() < end:
        for block in blocks:
            if block:
                block[0] = (block[0] + 1) % 256
        time.sleep(1)
except MemoryError:
    print(f"[memory] MemoryError after {allocated} MB; holding what was allocated", flush=True)
    time.sleep(duration)
PY
    PIDS+=("$!")
}

start_sensitive_exec_probes() {
    log "${GREEN}[alerts] 启动敏感命令 execve 探针${NC}"
    (
        local end_ts=$((SECONDS + DURATION))
        while [ "$SECONDS" -lt "$end_ts" ]; do
            chmod --version >/dev/null 2>&1 || chmod --help >/dev/null 2>&1 || true
            if have_cmd chattr; then chattr -V >/dev/null 2>&1 || true; fi
            if have_cmd tcpdump; then tcpdump --version >/dev/null 2>&1 || true; fi
            if have_cmd nmap; then nmap --version >/dev/null 2>&1 || true; fi
            if have_cmd nc; then nc -h >/dev/null 2>&1 || true; fi
            sleep 2
        done
    ) &
    PIDS+=("$!")
}

start_local_traffic() {
    [ "$LOCAL_TRAFFIC" -eq 1 ] || return 0
    have_cmd curl || {
        log "${YELLOW}[alerts] curl 不存在，跳过本机流量探针${NC}"
        return 0
    }

    log "${GREEN}[alerts] 启动本机 HTTP 流量，触发系统网速告警${NC}"
    (
        local end_ts=$((SECONDS + DURATION))
        while [ "$SECONDS" -lt "$end_ts" ]; do
            curl -fsS "${SENTINEL_URL}/assets/app.js" -o /dev/null 2>/dev/null || true
        done
    ) &
    PIDS+=("$!")
}

start_suspicious_network_probe() {
    [ "$SUSPICIOUS_NETWORK" -eq 1 ] || return 0

    log "${GREEN}[alerts] 尝试访问 ${NETWORK_TARGET}:${SUSPICIOUS_PORT}，触发可疑端口网络事件${NC}"
    (
        local end_ts=$((SECONDS + DURATION))
        while [ "$SECONDS" -lt "$end_ts" ]; do
            if have_cmd timeout; then
                timeout 1 bash -c ":</dev/tcp/${NETWORK_TARGET}/${SUSPICIOUS_PORT}" >/dev/null 2>&1 || true
            else
                bash -c ":</dev/tcp/${NETWORK_TARGET}/${SUSPICIOUS_PORT}" >/dev/null 2>&1 || true
            fi
            sleep 1
        done
    ) &
    PIDS+=("$!")
}

start_alert_probes() {
    configure_alerts
    start_sensitive_exec_probes
    start_local_traffic
    start_suspicious_network_probe
}

print_summary() {
    log "${BLUE}========================================${NC}"
    log "${BLUE}   eBPF Sentinel 压力测试${NC}"
    log "${BLUE}========================================${NC}"
    log ""
    log "${YELLOW}参数:${NC}"
    log "  模式: ${MODE}"
    log "  持续时间: ${DURATION} 秒"
    log "  编译 worker: ${CPU_JOBS}"
    log "  Go 函数数量/worker: ${GO_FUNCS}"
    if [ -n "$MEM_MB" ]; then
        log "  内存分配: ${MEM_MB} MB"
    else
        log "  目标内存使用率: ${MEM_PERCENT}%"
    fi
    log "  Sentinel URL: ${SENTINEL_URL}"
    log ""
    log "${YELLOW}当前系统:${NC}"
    log "  CPU 核心: $(nproc 2>/dev/null || echo unknown)"
    if have_cmd free; then
        log "  内存: $(free -h | awk '/^Mem:/ {print $2}')"
    fi
    log ""
}

confirm_start() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    log "${YELLOW}该脚本会显著提高 CPU、内存和本机网络流量。${NC}"
    read -r -p "确认开始? [y/N] " answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *) die "已取消" ;;
    esac
}

main() {
    parse_args "$@"
    WORKDIR="$(mktemp -d /tmp/ebpf-sentinel-stress.XXXXXX)"
    trap cleanup EXIT INT TERM

    print_summary
    confirm_start

    case "$MODE" in
        all)
            start_compile_pressure
            start_memory_pressure
            start_alert_probes
            ;;
        cpu)
            start_compile_pressure
            ;;
        memory)
            start_memory_pressure
            ;;
        alerts)
            start_alert_probes
            ;;
    esac

    log "${GREEN}测试运行中，${DURATION} 秒后自动结束。Ctrl+C 可提前停止。${NC}"
    sleep "$DURATION"
    log "${GREEN}压力测试完成。${NC}"
    log "${BLUE}建议检查:${NC}"
    log "  curl ${SENTINEL_URL}/api/alerts?history=true"
    log "  curl ${SENTINEL_URL}/api/events"
    log "  curl ${SENTINEL_URL}/api/network-events"
}

main "$@"
