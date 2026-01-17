cmake_minimum_required(VERSION 3.15)
project(PSI C)

# ==============================
# 🔧 基础配置
# ==============================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ==============================
# 📦 查找依赖库
# ==============================
if(APPLE)
    message(STATUS "🍎 macOS 环境检测到，使用 Homebrew 路径配置")

    # Homebrew 路径
    set(HOMEBREW_PREFIX "/opt/homebrew")

    # OpenMP (macOS 上 Clang 默认不支持，需要 libomp)
    set(OpenMP_C_FLAGS "-Xpreprocessor -fopenmp")
    set(OpenMP_C_LIB_NAMES "omp")
    set(OpenMP_omp_LIBRARY "${HOMEBREW_PREFIX}/opt/libomp/lib/libomp.dylib")
    include_directories("${HOMEBREW_PREFIX}/opt/libomp/include")
    link_directories("${HOMEBREW_PREFIX}/opt/libomp/lib")

    # GMP
    include_directories("${HOMEBREW_PREFIX}/opt/gmp/include")
    link_directories("${HOMEBREW_PREFIX}/opt/gmp/lib")

    # OpenSSL
    include_directories("${HOMEBREW_PREFIX}/opt/openssl/include")
    link_directories("${HOMEBREW_PREFIX}/opt/openssl/lib")
else()
    message(STATUS "🐧 Linux 环境检测到，使用系统路径配置")
endif()

# ==============================
# 🧵 OpenMP 配置
# ==============================
find_package(OpenMP REQUIRED)
if(OpenMP_C_FOUND)
    message(STATUS "✅ OpenMP 检测成功")
else()
    message(FATAL_ERROR "❌ 未找到 OpenMP，请确认编译器支持 -fopenmp")
endif()

# ==============================
# 📝 源文件
# ==============================
set(SOURCES
    main.c
    PSI.c
    PSI_Cloud.c
    client.c
    Verify.c
    Beaver_Cloud.c
    beaver.c
    bucket.c
    crt_gmp.c
    crypt.c
    dataset.c
    fft_poly.c
    hash.c
    modsystem.c
)

set(HEADERS
    PSI.h
    PSI_Cloud.h
    client.h
    Verify.h
    Beaver_Cloud.h
    beaver.h
    bucket.h
    crt_gmp.h
    crypt.h
    dataset.h
    fft_poly.h
    hash.h
    modsystem.h
)

# ==============================
# 🎯 可执行文件目标
# ==============================
add_executable(psi_program ${SOURCES} ${HEADERS})
add_executable(psi_program_debug ${SOURCES} ${HEADERS})

# ==============================
# ⚙️ 编译选项
# ==============================
target_compile_options(psi_program PRIVATE
    -Wall
    -O2
    -g
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
)

target_compile_options(psi_program_debug PRIVATE
    -Wall
    -O0
    -g
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
)

# ==============================
# 🔗 链接库
# ==============================
target_link_libraries(psi_program PRIVATE
    gmp
    crypto
    ssl
    m
    pthread
    OpenMP::OpenMP_C
)

target_link_libraries(psi_program_debug PRIVATE
    gmp
    crypto
    ssl
    m
    pthread
    OpenMP::OpenMP_C
)

target_link_options(psi_program_debug PRIVATE
    -fsanitize=address
)

# ==============================
# 📄 安装配置
# ==============================
install(TARGETS psi_program
    RUNTIME DESTINATION bin
)

# ==============================
# 💬 提示信息
# ==============================
message(STATUS "")
message(STATUS "🔧 PSI 项目配置完成")
message(STATUS "📦 输出目录: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "📝 compile_commands.json 将生成在构建目录")
message(STATUS "")
message(STATUS "💡 构建步骤:")
message(STATUS "   mkdir -p build && cd build")
message(STATUS "   cmake ..")
message(STATUS "   make -j$(nproc)")
message(STATUS "")
message(STATUS "💡 运行前可设置 AddressSanitizer:")
message(STATUS "   export ASAN_OPTIONS=fast_unwind_on_malloc=0:malloc_context_size=50")