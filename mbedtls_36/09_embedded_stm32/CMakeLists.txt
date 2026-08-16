# =====================================================================
# mbedTLS 3.6 + STM32F407 + FreeRTOS —— 嵌入式交叉编译工程
#
# 这是一个【独立】的交叉编译子工程，与上层 mbedtls_36/ 的原机（native）
# 示例互不影响。它演示三件事：
#   1. 交叉编译：用 arm-none-eabi-gcc 把 mbedTLS + FreeRTOS + 应用编译成
#      STM32F407VE 的 .elf / .bin / .hex
#   2. 裁剪：通过 MBEDTLS_USER_CONFIG_FILE 关闭 RSA/TLS/X509/PSA 等大模块，
#      只保留本示例用到的 SHA-256 / AES-CBC / ECDSA
#   3. 集成：把 mbedTLS 的"可替换接口"（熵源 / 互斥锁 / I/O）接到
#      STM32 硬件 + FreeRTOS 上（见 port/ 目录）
#
# 构建方式见同目录 build.sh。
# =====================================================================

cmake_minimum_required(VERSION 3.14)
project(mbedtls_36_embedded_stm32 C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------
# 一、mbedTLS 3.6.0（FetchContent）
# ---------------------------------------------------------------------
include(FetchContent)

# 裁剪配置：必须在 FetchContent_MakeAvailable(mbedtls) 【之前】设置，
# 因为 mbedTLS 的 CMake 在配置阶段读取 MBEDTLS_USER_CONFIG_FILE。
# 该变量是 FILEPATH 缓存变量，mbedTLS 会把它作为 PUBLIC 编译定义
# （MBEDTLS_USER_CONFIG_FILE="..."）传给 mbedcrypto/mbedx509/mbedtls 目标。
set(MBEDTLS_USER_CONFIG_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_user_config_stm32.h
    CACHE FILEPATH "mbedTLS user config (trimming)" FORCE)

# 关闭测试与示例程序，加速构建；强制静态库（裸机不能用共享库）
set(ENABLE_TESTING            OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS           OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON  CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
)
FetchContent_MakeAvailable(mbedtls)

# 裁剪配置开启了 MBEDTLS_THREADING_ALT，threading.h 会 #include "threading_alt.h"。
# 该头文件在 port/ 目录（FreeRTOS 互斥锁封装），需要加入 mbedcrypto 的包含路径。
target_include_directories(mbedcrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/port)

# ---------------------------------------------------------------------
# 二、FreeRTOS-Kernel V11.3.0（FetchContent，显式静态库）
# ---------------------------------------------------------------------
# 不采用 FreeRTOS 官方 CMake：它的 CMakeLists.txt 要求调用方先创建
# freertos_config 目标并指定 FREERTOS_PORT/FREERTOS_HEAP，且会自建一个
# FreeRTOS 目标。为了教学直观、可控，这里只用 FetchContent_Populate()
# 【下载源码】（不执行其 CMakeLists.txt），然后自己把
# "内核核心 + CM4F 端口 + heap_4" 编成一个静态库。
FetchContent_Declare(
    freertos_kernel
    GIT_REPOSITORY https://github.com/FreeRTOS/FreeRTOS-Kernel.git
    GIT_TAG        V11.3.0
)
# Populate 只负责获取源码，得到 ${freertos_kernel_SOURCE_DIR}，不运行其 CMake
FetchContent_Populate(freertos_kernel)

# freertos_config：INTERFACE 目标，提供 FreeRTOSConfig.h 所在目录（port/）
add_library(freertos_config INTERFACE)
target_include_directories(freertos_config INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/port)

# FreeRTOS 静态库：7 个核心文件 + ARM_CM4F 端口 + heap_4
add_library(freertos STATIC
    ${freertos_kernel_SOURCE_DIR}/croutine.c
    ${freertos_kernel_SOURCE_DIR}/list.c
    ${freertos_kernel_SOURCE_DIR}/queue.c
    ${freertos_kernel_SOURCE_DIR}/stream_buffer.c
    ${freertos_kernel_SOURCE_DIR}/tasks.c
    ${freertos_kernel_SOURCE_DIR}/timers.c
    ${freertos_kernel_SOURCE_DIR}/event_groups.c
    ${freertos_kernel_SOURCE_DIR}/portable/GCC/ARM_CM4F/port.c
    ${freertos_kernel_SOURCE_DIR}/portable/MemMang/heap_4.c
)
target_include_directories(freertos PUBLIC
    ${freertos_kernel_SOURCE_DIR}/include
    ${freertos_kernel_SOURCE_DIR}/portable/GCC/ARM_CM4F)
target_link_libraries(freertos PUBLIC freertos_config)

# ---------------------------------------------------------------------
# 三、应用（STM32F407VE 固件）
# ---------------------------------------------------------------------
add_executable(app.elf
    main.c
    port/stm32f4_hw.c
    port/platform_glue.c
    port/startup_stm32f4.s
)

target_include_directories(app.elf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/port)

# 链接：
#   mbedcrypto —— 本示例用到的全部加密模块（sha256/aes/ecdsa/entropy/
#                 ctr_drbg/error/threading）都在 mbedcrypto 里，无需 x509/tls
#   freertos   —— FreeRTOS 内核 + CM4F 端口
target_link_libraries(app.elf PRIVATE
    mbedcrypto
    freertos
)

# 裸机链接：使用自定义链接脚本（内存布局），不引入 newlib 的 crt0
# （入口由 startup_stm32f4.s 的 Reset_Handler 决定，见链接脚本 ENTRY）
set(LD_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/port/stm32f407ve.ld)
set_target_properties(app.elf PROPERTIES LINK_DEPENDS ${LD_SCRIPT})
target_link_options(app.elf PRIVATE
    -T${LD_SCRIPT}
    -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/app.map
    -Wl,--gc-sections
    -nostartfiles
)

# 构建后：生成 .bin / .hex，并打印体积（text/data/bss）
add_custom_command(TARGET app.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:app.elf>
            ${CMAKE_CURRENT_BINARY_DIR}/app.bin
    COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:app.elf>
            ${CMAKE_CURRENT_BINARY_DIR}/app.hex
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:app.elf>
    COMMENT "生成 app.bin / app.hex 并打印体积"
)
