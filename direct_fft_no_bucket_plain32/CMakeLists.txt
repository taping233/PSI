cmake_minimum_required(VERSION 3.15)
project(DirectFFTNoBucket C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_executable(psi_direct_fft_no_bucket
    "${SRC_DIR}/main.c"
    "${SRC_DIR}/arrayutil.c"
    "${SRC_DIR}/crt_gmp.c"
    "${SRC_DIR}/fftutil8.c"
    "${SRC_DIR}/modsystem.c"
    "${SRC_DIR}/primitive.c"
    "${SRC_DIR}/tg_roots.c"
    "${SRC_DIR}/ntl_backend.cpp"
)

target_include_directories(psi_direct_fft_no_bucket PRIVATE "${INCLUDE_DIR}")

target_compile_options(psi_direct_fft_no_bucket PRIVATE
    -Wall
    -Wextra
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
    $<$<CONFIG:Debug>:-fno-optimize-sibling-calls>
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Release>:-march=native>
)

if(ENABLE_SANITIZERS)
    target_compile_options(psi_direct_fft_no_bucket PRIVATE
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=address,undefined
    )
    target_link_options(psi_direct_fft_no_bucket PRIVATE
        -fsanitize=address,undefined
    )
endif()

target_link_libraries(psi_direct_fft_no_bucket PRIVATE
    gmp
    gmpxx
    flint
    ntl
    m
    pthread
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenMP::OpenMP_C
)

add_executable(dpsi_poly_backend
    "${SRC_DIR}/dpsi_poly_backend.cpp"
)

target_compile_options(dpsi_poly_backend PRIVATE
    -Wall
    -Wextra
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Release>:-march=native>
)

target_link_libraries(dpsi_poly_backend PRIVATE
    flint
    ntl
    gmp
    gmpxx
)
