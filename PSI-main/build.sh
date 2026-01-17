#!/bin/bash
# ==============================
# 🔧 PSI 项目编译脚本
# ==============================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 编译目录
OUTPUT_DIR="output"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}==============================${NC}"
echo -e "${BLUE}🚀 开始编译 PSI 项目${NC}"
echo -e "${BLUE}==============================${NC}"
echo ""

# 创建 output 目录
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}📁 创建 output 目录...${NC}"
    mkdir -p "$OUTPUT_DIR"
fi

# 清理旧的编译产物
echo -e "${YELLOW}🧹 清理旧的编译产物...${NC}"
make clean > /dev/null 2>&1 || true
rm -rf "$OUTPUT_DIR"/*.o "$OUTPUT_DIR"/psi_program "$OUTPUT_DIR"/psi_program_debug

# 编译项目
echo -e "${BLUE}🔨 开始编译...${NC}"
echo ""

if make OUTPUT_DIR="$OUTPUT_DIR"; then
    echo ""
    echo -e "${GREEN}✅ 编译成功！${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}📦 编译产物已输出到: ${OUTPUT_DIR}/${NC}"
    echo ""
    
    # 显示生成的文件
    if [ -f "$OUTPUT_DIR/psi_program" ]; then
        SIZE=$(du -h "$OUTPUT_DIR/psi_program" | cut -f1)
        echo -e "  ✓ psi_program (${SIZE})"
    fi
    
    echo ""
    echo -e "${BLUE}💡 运行提示:${NC}"
    echo -e "  ${YELLOW}export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50${NC}"
    echo -e "  ${YELLOW}./${OUTPUT_DIR}/psi_program${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}❌ 编译失败！${NC}"
    echo -e "${RED}请检查上面的错误信息${NC}"
    exit 1
fi


