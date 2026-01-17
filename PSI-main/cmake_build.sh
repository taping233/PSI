#!/bin/bash
# ==============================
# 🔧 PSI 项目 CMake 编译脚本
# ==============================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 构建目录
BUILD_DIR="output"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}==============================${NC}"
echo -e "${BLUE}🚀 CMake 构建 PSI 项目${NC}"
echo -e "${BLUE}==============================${NC}"
echo ""

# 创建构建目录
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}📁 创建构建目录: $BUILD_DIR${NC}"
    mkdir -p "$BUILD_DIR"
fi

# 进入构建目录
cd "$BUILD_DIR"

# 运行 CMake 配置
echo -e "${BLUE}🔧 运行 CMake 配置...${NC}"
if cmake -DCMAKE_BUILD_TYPE=Release ..; then
    echo -e "${GREEN}✅ CMake 配置成功${NC}"
    echo ""
else
    echo -e "${RED}❌ CMake 配置失败！${NC}"
    exit 1
fi

# 编译项目
echo -e "${BLUE}🔨 开始编译...${NC}"
echo ""

if make -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4); then
    echo ""
    echo -e "${GREEN}✅ 编译成功！${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 复制 compile_commands.json 到项目根目录
    if [ -f "compile_commands.json" ]; then
        cp compile_commands.json ..
        echo -e "${GREEN}📝 compile_commands.json 已复制到项目根目录${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}📦 编译产物:${NC}"
    
    # 显示生成的文件
    if [ -f "psi_program" ]; then
        SIZE=$(du -h "psi_program" | cut -f1)
        echo -e "  ✓ psi_program (${SIZE})"
    fi
    
    if [ -f "psi_program_debug" ]; then
        SIZE=$(du -h "psi_program_debug" | cut -f1)
        echo -e "  ✓ psi_program_debug (${SIZE})"
    fi
    
    echo ""
    echo -e "${BLUE}💡 运行提示:${NC}"
    echo -e "  ${YELLOW}export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50${NC}"
    echo -e "  ${YELLOW}./${BUILD_DIR}/psi_program${NC}"
    echo ""
    echo -e "${BLUE}💡 clangd 配置:${NC}"
    echo -e "  ${GREEN}compile_commands.json 已生成，clangd 会自动识别${NC}"
    echo ""
else
    echo ""
    echo -e "${RED}❌ 编译失败！${NC}"
    echo -e "${RED}请检查上面的错误信息${NC}"
    exit 1
fi


