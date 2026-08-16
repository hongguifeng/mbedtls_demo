# CMake 交叉编译工具链文件：ARM Cortex-M4 (STM32F4) + GNU Arm Embedded Toolchain
#
# 用法：cmake -DCMAKE_TOOLCHAIN_FILE=arm-none-eabi.cmake ..
#
# 关键点：
#   -mcpu=cortex-m4        目标 CPU（带 FPU）
#   -mthumb                Thumb-2 指令集
#   -mfpu=fpv4-sp-d16      STM32F4 的单精度 FPU
#   -mfloat-abi=hard       硬件浮点调用约定（FreeRTOS ARM_CM4F 端口要求）
#   -specs=nosys.specs     使用 newlib-nano 的 nosys 桩，避免依赖完整 POSIX
#   -specs=nan.specs       精简 libc（newlib-nano），显著减小体积

set(CMAKE_SYSTEM_NAME   Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# 工具链前缀
set(CROSS_PREFIX arm-none-eabi-)
set(CMAKE_C_COMPILER   ${CROSS_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CROSS_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${CROSS_PREFIX}g++)
set(CMAKE_OBJCOPY      ${CROSS_PREFIX}objcopy)
set(CMAKE_SIZE         ${CROSS_PREFIX}size)

# 避免在配置阶段尝试运行目标程序（交叉编译无法在本机执行）
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# 目标架构相关编译选项
# QEMU_EMU=ON（由 build.sh qemu 模式传入 -DQEMU_EMU=ON）：
#   目标为 QEMU mps2-an385 的 Cortex-M3 —— 无 FPU，必须 soft-float，
#   且 FreeRTOS 端口换成 ARM_CM3（见 CMakeLists.txt）。
if(QEMU_EMU)
    set(MCU_FLAGS "-mcpu=cortex-m3 -mthumb")
else()
    set(MCU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
endif()

set(CMAKE_C_FLAGS_INIT   "${MCU_FLAGS} -ffunction-sections -fdata-sections -fno-common")
set(CMAKE_ASM_FLAGS_INIT "${MCU_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${MCU_FLAGS} -ffunction-sections -fdata-sections")

# 链接选项：去掉未使用的 section（配合 -ffunction/-fdata-sections），使用 newlib-nano
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "${MCU_FLAGS} -Wl,--gc-sections --specs=nosys.specs --specs=nano.specs")

# 安装到本机（交叉编译通常不 install）
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
