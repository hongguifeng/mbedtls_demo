# ============================================================================
# mbedTLS 4.2 (PSA Crypto API) + FreeRTOS on STM32F407VE — 交叉编译示例
#
# 与 mbedtls_36/09_embedded_stm32 的区别：
#   - 链接目标从 mbedcrypto 换成 tfpsacrypto（4.x 拆分出的独立 crypto 库）
#   - 裁剪入口从 MBEDTLS_USER_CONFIG_FILE 换成 TF_PSA_CRYPTO_USER_CONFIG_FILE
#     （4.x 中 crypto 配置在 tf-psa-crypto/include/psa/crypto_config.h，
#      用 PSA_WANT_* 宏做预处理器级裁剪）
#   - 线程互斥锁回调从 4 个增加到 9 个（新增条件变量，库内未使用，桩实现即可）
#   - 熵源接口从 mbedtls_hardware_poll 换成 mbedtls_platform_get_entropy
#
# 构建：./build.sh  （需要 arm-none-eabi-gcc + cmake >= 3.14）
# ============================================================================
cmake_minimum_required(VERSION 3.14)

project(mbedtls_42_embedded_stm32 C ASM)

# QEMU_EMU=ON：构建为 QEMU mps2-an385（Cortex-M3，无 FPU）可运行的固件。
#   - FreeRTOS 端口 ARM_CM4F → ARM_CM3（soft-float）
#   - 硬件层 stm32f4_hw.c → qemu_hw.c（CMSDK APB UART + 软件 PRNG）
#   - 启动文件 startup_stm32f4.s → startup_qemu.s（.cpu cortex-m3，无 .fpu）
#   - 链接脚本 stm32f407ve.ld → qemu_mps2.ld（Flash @ 0x00000000）
# 用法：./build.sh qemu
option(QEMU_EMU "Build for QEMU mps2-an385 (Cortex-M3) instead of STM32F407VE" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ----------------------------------------------------------------------------
# 1. mbedTLS 4.2.0（含 tf-psa-crypto / framework 子模块）
#    裁剪配置：TF_PSA_CRYPTO_USER_CONFIG_FILE 必须在 MakeAvailable 之前设置，
#    它会被 tf-psa-crypto 以 PUBLIC 编译定义的形式传给所有目标。
# ----------------------------------------------------------------------------
set(TF_PSA_CRYPTO_USER_CONFIG_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/port/psa_user_config_stm32.h
    CACHE FILEPATH "" FORCE)

include(FetchContent)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v4.2.0
    GIT_SUBMODULES "tf-psa-crypto" "framework"
)

# 只构建静态库，关闭测试与示例程序（嵌入式场景不需要）
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

# threading_alt.h 位于 port/ 目录。4.2 的 mbedtls/threading.h 在
# MBEDTLS_THREADING_ALT 下执行的是【裸文件名】 #include "threading_alt.h"，
# 且 tf-psa-crypto 内部拆成 platform/utilities/extras/core 等多个对象库目标，
# 对 tfpsacrypto 做 target_include_directories 覆盖不到它们，
# 因此用目录级 include 路径（对之后创建的所有目标生效）。
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/port)

FetchContent_MakeAvailable(mbedtls)

# ----------------------------------------------------------------------------
# 2. FreeRTOS-Kernel（V11.3.0）
#    只取内核核心 + Cortex-M4F 端口 + heap_4，不引入 CMSIS / HAL。
# ----------------------------------------------------------------------------
include(FetchContent)
FetchContent_Populate(freertos_kernel
    GIT_REPOSITORY https://github.com/FreeRTOS/FreeRTOS-Kernel.git
    GIT_TAG        V11.3.0
)

# 按目标选择 FreeRTOS 端口：STM32F407 = CM4F（hard-float），QEMU MPS2 = CM3（soft-float）
if(QEMU_EMU)
    set(FREERTOS_PORT_DIR ${freertos_kernel_SOURCE_DIR}/portable/GCC/ARM_CM3)
else()
    set(FREERTOS_PORT_DIR ${freertos_kernel_SOURCE_DIR}/portable/GCC/ARM_CM4F)
endif()

add_library(freertos_config INTERFACE)
target_include_directories(freertos_config INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/port          # FreeRTOSConfig.h
)
# QEMU_EMU 宏：FreeRTOSConfig.h 用它把时钟从 168MHz 切到 25MHz（MPS2 SYSCLK）。
# 挂在 freertos_config 上，随 freertos PUBLIC 传播给 app.elf（platform_glue.c
# 的 vPortSetupTimerInterrupt 也依赖 configSYSTICK_CLOCK_HZ）。
if(QEMU_EMU)
    target_compile_definitions(freertos_config INTERFACE QEMU_EMU)
endif()

add_library(freertos STATIC
    ${freertos_kernel_SOURCE_DIR}/croutine.c
    ${freertos_kernel_SOURCE_DIR}/list.c
    ${freertos_kernel_SOURCE_DIR}/queue.c
    ${freertos_kernel_SOURCE_DIR}/stream_buffer.c
    ${freertos_kernel_SOURCE_DIR}/tasks.c
    ${freertos_kernel_SOURCE_DIR}/timers.c
    ${freertos_kernel_SOURCE_DIR}/event_groups.c
    ${FREERTOS_PORT_DIR}/port.c
    ${freertos_kernel_SOURCE_DIR}/portable/MemMang/heap_4.c
)
target_include_directories(freertos PUBLIC
    ${freertos_kernel_SOURCE_DIR}/include
    ${FREERTOS_PORT_DIR}
)
target_link_libraries(freertos PUBLIC freertos_config)

# ----------------------------------------------------------------------------
# 3. 应用固件 app.elf
# ----------------------------------------------------------------------------
if(QEMU_EMU)
    set(HW_SOURCE      port/qemu_hw.c)        # CMSDK APB UART + 软件 PRNG
    set(STARTUP_SOURCE port/startup_qemu.s)   # .cpu cortex-m3，无 FPU
    set(LD_SCRIPT      ${CMAKE_CURRENT_SOURCE_DIR}/port/qemu_mps2.ld)
else()
    set(HW_SOURCE      port/stm32f4_hw.c)     # 手写硬件层：SystemInit / UART / RNG
    set(STARTUP_SOURCE port/startup_stm32f4.s)# 启动文件 + 向量表
    set(LD_SCRIPT      ${CMAKE_CURRENT_SOURCE_DIR}/port/stm32f407ve.ld)
endif()

add_executable(app.elf
    main.c
    ${HW_SOURCE}
    port/platform_glue.c     # _write / SysTick / 熵源 / 线程互斥锁回调
    ${STARTUP_SOURCE}
)

target_link_libraries(app.elf PRIVATE
    tfpsacrypto              # mbedTLS 4.2 的 crypto 库（PSA API）
    freertos
)

# 链接脚本作为链接依赖，改动后自动重新链接
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
