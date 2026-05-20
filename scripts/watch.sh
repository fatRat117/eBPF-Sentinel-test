#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== eBPF-Sentinel 文件监控自动编译 ===${NC}"
echo -e "${YELLOW}监控所有 .go 文件的变化，保存后自动编译并测试${NC}"
echo -e "按 Ctrl+C 停止监控"
echo ""

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# 检查 inotifywait 是否安装
if ! command -v inotifywait &> /dev/null; then
    echo -e "${RED}错误: inotifywait 未安装${NC}"
    echo "请安装 inotify-tools:"
    echo "  Ubuntu/Debian: sudo apt-get install inotify-tools"
    echo "  CentOS/RHEL:   sudo yum install inotify-tools"
    exit 1
fi

# 首次编译
echo -e "${YELLOW}[首次编译]${NC}"
"$PROJECT_ROOT/scripts/build.sh"

echo ""
echo -e "${BLUE}开始监控文件变化...${NC}"
echo ""

# 监控所有 .go 文件的变化
inotifywait -m -r -e modify,move,create,delete \
    --include '.*\.go$' \
    "$PROJECT_ROOT" \
    --format '%w%f' |
while read -r file; do
    # 忽略 go.sum 和 go.mod 的变化（除非你确实想监控它们）
    if [[ "$file" == *"go.sum"* ]] || [[ "$file" == *".git"* ]]; then
        continue
    fi
    
    echo -e "${YELLOW}检测到文件变化: $file${NC}"
    echo -e "${YELLOW}正在重新编译...${NC}"
    echo ""
    
    # 执行编译和测试
    "$PROJECT_ROOT/scripts/build.sh"
    
    echo ""
    echo -e "${BLUE}继续监控...${NC}"
    echo ""
done
