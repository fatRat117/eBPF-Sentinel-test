#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== eBPF-Sentinel 构建脚本 ===${NC}"
echo ""

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# 编译
echo -e "${YELLOW}[1/2] 正在编译...${NC}"
if go build -o eBPF-Sentinel .; then
    echo -e "${GREEN}✓ 编译成功${NC}"
else
    echo -e "${RED}✗ 编译失败${NC}"
    exit 1
fi

echo ""

# 测试
echo -e "${YELLOW}[2/2] 正在运行测试...${NC}"
if go test ./... -v; then
    echo ""
    echo -e "${GREEN}✓ 所有测试通过${NC}"
else
    echo ""
    echo -e "${RED}✗ 测试失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== 构建完成 ===${NC}"
