#!/usr/bin/env bash
# =====================================================================
# mbedTLS 4.2 (PSA) + STM32F407 + FreeRTOS —— 交叉编译脚本
#
# 用法：
#   ./build.sh                 # 自动探测 arm-none-eabi-gcc（目标 STM32F407VE）
#   ./build.sh qemu            # 目标 QEMU mps2-an385（Cortex-M3，可仿真运行）
#   TOOLCHAIN=.../bin ./build.sh   # 显式指定工具链 bin 目录
#
# 产物（在 build-arm/ 或 build-qemu/ 下）：
#   app.elf / app.bin / app.hex / app.map
# 并打印 text/data/bss 体积。
# QEMU 模式构建后可用 ./run_qemu.sh 直接仿真运行。
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")"

# ---- 工具链探测 ------------------------------------------------------
if [[ -n "${TOOLCHAIN:-}" ]]; then
    export PATH="${TOOLCHAIN}:${PATH}"
fi

if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    # 常见安装位置兜底
    for cand in \
        "$HOME/code/gcc-arm-none-eabi-10-2020-q4-major/bin" \
        /opt/gcc-arm-none-eabi/bin \
        /usr/local/bin; do
        if [[ -x "$cand/arm-none-eabi-gcc" ]]; then
            export PATH="$cand:${PATH}"
            break
        fi
    done
fi

if ! command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    echo "错误：找不到 arm-none-eabi-gcc。" >&2
    echo "请安装 GNU Arm Embedded Toolchain，或用 TOOLCHAIN=/path/to/bin ./build.sh 指定。" >&2
    exit 1
fi

echo "使用工具链：$(command -v arm-none-eabi-gcc)"
arm-none-eabi-gcc --version | head -1

# ---- 配置 + 编译 -----------------------------------------------------
# 目标选择：./build.sh qemu → QEMU mps2-an385（Cortex-M3）
QEMU_MODE=0
if [[ "${1:-}" == "qemu" ]]; then
    QEMU_MODE=1
fi

# QEMU 模式用独立构建目录：工具链 flags / FreeRTOS 端口 / 链接脚本都不同，
# 与 STM32 构建互不污染缓存。
if [[ "$QEMU_MODE" -eq 1 ]]; then
    BUILD_DIR=build-qemu
else
    BUILD_DIR=build-arm
fi
JOBS="$(nproc 2>/dev/null || echo 4)"

# 可选：复用已有的 mbedTLS 源码树（避免重新 clone，需含 tf-psa-crypto/framework 子模块）
#   例：MBEDTLS_SRC=$PWD/../../build/_deps/mbedtls-src ./build.sh
CMAKE_EXTRA_ARGS=()
if [[ -n "${MBEDTLS_SRC:-}" ]]; then
    CMAKE_EXTRA_ARGS+=("-DFETCHCONTENT_SOURCE_DIR_MBEDTLS=${MBEDTLS_SRC}")
fi
if [[ "$QEMU_MODE" -eq 1 ]]; then
    CMAKE_EXTRA_ARGS+=("-DQEMU_EMU=ON")
fi

cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE=arm-none-eabi.cmake \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DMBEDTLS_FATAL_WARNINGS=OFF \
    ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"}

# 只构建 app.elf（它只依赖 tfpsacrypto + freertos），避免编译用不到的
# TLS/X.509 库（其中 net_sockets.c 等依赖 POSIX，裸机无法编译）。
cmake --build "$BUILD_DIR" --target app.elf -j"$JOBS"

echo
echo "================ 构建完成 ================"
ls -lh "$BUILD_DIR"/app.elf "$BUILD_DIR"/app.bin "$BUILD_DIR"/app.hex 2>/dev/null || true
echo
echo "（体积 text/data/bss 见上方 arm-none-eabi-size 输出）"

if [[ "$QEMU_MODE" -eq 1 ]]; then
    echo
    echo "QEMU 模式：运行 ./run_qemu.sh 即可在 mps2-an385 上仿真执行。"
fi
