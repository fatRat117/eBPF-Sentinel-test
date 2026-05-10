#!/bin/bash
# eBPF Sentinel 压力测试脚本
# 模拟大量execve系统调用

set -e

# 默认参数
DURATION=30          # 测试持续时间(秒)
PARALLEL=50          # 并行进程数
INTERVAL=0.01        # 每次调用的间隔(秒)
MODE="mixed"         # 测试模式: fork|exec|mixed

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 帮助信息
usage() {
    echo -e "${BLUE}eBPF Sentinel 压力测试脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -d, --duration    测试持续时间(秒), 默认: 30"
    echo "  -p, --parallel    并行进程数, 默认: 50"
    echo "  -i, --interval    调用间隔(秒), 默认: 0.01"
    echo "  -m, --mode        测试模式: fork|exec|mixed, 默认: mixed"
    echo "  -h, --help        显示帮助"
    echo ""
    echo "示例:"
    echo "  $0                                    # 使用默认参数运行"
    echo "  $0 -d 60 -p 100                       # 运行60秒, 100个并行进程"
    echo "  $0 -m exec -i 0.001                   # exec模式, 1ms间隔"
    echo ""
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        -i|--interval)
            INTERVAL="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}未知选项: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# 验证参数
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -lt 1 ]; then
    echo -e "${RED}错误: 持续时间必须是正整数${NC}"
    exit 1
fi

if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [ "$PARALLEL" -lt 1 ]; then
    echo -e "${RED}错误: 并行数必须是正整数${NC}"
    exit 1
fi

if ! [[ "$INTERVAL" =~ ^[0-9]*\.?[0-9]+$ ]] || [ "$(echo "$INTERVAL <= 0" | bc -l)" -eq 1 ]; then
    echo -e "${RED}错误: 间隔必须是正数${NC}"
    exit 1
fi

# 测试模式函数
test_fork() {
    # 只创建子进程,不执行新程序
    local end_time=$(($(date +%s) + DURATION))
    local count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=0; i<PARALLEL; i++)); do
            (
                # 创建子进程后立即退出
                (exit 0)
            ) &
        done
        wait
        count=$((count + PARALLEL))
        sleep "$INTERVAL"
    done
    
    echo "$count"
}

test_exec() {
    # 执行各种系统命令
    local end_time=$(($(date +%s) + DURATION))
    local count=0
    local commands=(
        "true"
        "echo test"
        "date"
        "whoami"
        "pwd"
        "uname"
        "id"
        "hostname"
        "cat /proc/version"
        "ls /tmp"
    )
    local num_commands=${#commands[@]}
    
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=0; i<PARALLEL; i++)); do
            (
                local cmd_idx=$((RANDOM % num_commands))
                eval "${commands[$cmd_idx]}" > /dev/null 2>&1 || true
            ) &
        done
        wait
        count=$((count + PARALLEL))
        sleep "$INTERVAL"
    done
    
    echo "$count"
}

test_mixed() {
    # 混合模式: 既有fork又有exec
    local end_time=$(($(date +%s) + DURATION))
    local count=0
    local commands=(
        "true"
        "echo"
        "date"
        "whoami"
        "pwd"
    )
    local num_commands=${#commands[@]}
    
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=0; i<PARALLEL; i++)); do
            (
                if [ $((RANDOM % 2)) -eq 0 ]; then
                    # 50%概率执行命令
                    local cmd_idx=$((RANDOM % num_commands))
                    eval "${commands[$cmd_idx]}" > /dev/null 2>&1 || true
                else
                    # 50%概率创建子shell
                    (exit 0)
                fi
            ) &
        done
        wait
        count=$((count + PARALLEL))
        sleep "$INTERVAL"
    done
    
    echo "$count"
}

# 主函数
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   eBPF Sentinel 压力测试${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}测试参数:${NC}"
    echo "  持续时间: ${DURATION}秒"
    echo "  并行进程: ${PARALLEL}"
    echo "  调用间隔: ${INTERVAL}秒"
    echo "  测试模式: ${MODE}"
    echo ""
    
    # 检查系统资源
    echo -e "${YELLOW}系统状态:${NC}"
    echo "  CPU核心数: $(nproc)"
    echo "  内存: $(free -h | awk '/^Mem:/ {print $2}')"
    echo "  当前进程数: $(ps aux | wc -l)"
    echo ""
    
    # 预估调用次数
    local estimated_calls=$(awk "BEGIN {printf \"%d\", ($DURATION / $INTERVAL) * $PARALLEL}")
    echo -e "${YELLOW}预计执行调用次数: ~$estimated_calls${NC}"
    echo ""
    
    read -p "按回车键开始测试, Ctrl+C 停止..."
    echo ""
    
    # 记录开始时间
    local start_time=$(date +%s)
    local start_processes=$(ps aux | wc -l)
    
    echo -e "${GREEN}开始测试...${NC}"
    echo ""
    
    # 根据模式执行测试
    case $MODE in
        fork)
            total_calls=$(test_fork)
            ;;
        exec)
            total_calls=$(test_exec)
            ;;
        mixed)
            total_calls=$(test_mixed)
            ;;
        *)
            echo -e "${RED}错误: 未知的测试模式: $MODE${NC}"
            exit 1
            ;;
    esac
    
    # 记录结束时间
    local end_time=$(date +%s)
    local actual_duration=$((end_time - start_time))
    local end_processes=$(ps aux | wc -l)
    
    # 计算统计信息
    local calls_per_second=$(echo "scale=2; $total_calls / $actual_duration" | bc -l)
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   测试完成!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}测试结果:${NC}"
    echo "  实际持续时间: ${actual_duration}秒"
    echo "  总调用次数: $total_calls"
    echo "  平均每秒调用: $calls_per_second"
    echo "  进程数变化: ${start_processes} -> ${end_processes}"
    echo ""
    echo -e "${BLUE}建议:${NC}"
    echo "  1. 检查eBPF Sentinel日志确认事件捕获"
    echo "  2. 访问 http://localhost:8080 查看Web界面"
    echo "  3. 调用API: curl http://localhost:8080/api/events"
    echo ""
}

# 捕获Ctrl+C
trap 'echo -e "\n${YELLOW}测试被用户中断${NC}"; exit 0' INT

# 运行主函数
main
