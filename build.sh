#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=============================================="
echo "  mbedTLS 教程 - 总构建脚本"
echo "=============================================="
echo ""

# Build mbedTLS 3.6 sub-project
echo ">>> [1/3] 构建 mbedtls_36 (mbedTLS 3.6.0 LTS)"
echo ""
cd mbedtls_36
./build.sh
cd ..

echo ""
echo ">>> [2/3] 构建 mbedtls_42 (mbedTLS 4.2.0 PSA Crypto)"
echo ""
cd mbedtls_42
./build.sh
cd ..

# 嵌入式交叉编译示例（需要 arm-none-eabi-gcc，找不到则跳过）
if command -v arm-none-eabi-gcc >/dev/null 2>&1 || [[ -x "$HOME/code/gcc-arm-none-eabi-10-2020-q4-major/bin/arm-none-eabi-gcc" ]]; then
    echo ""
    echo ">>> [3/3] 构建嵌入式示例 (STM32F407 + FreeRTOS, 交叉编译)"
    echo ""
    for ex in mbedtls_36/09_embedded_stm32 mbedtls_42/16_embedded_stm32; do
        echo ">>> 构建 $ex"
        # 若 [1/3]/[2/3] 的原生构建已拉取 mbedtls 源码，则复用，避免重复 clone
        ver="${ex%%/*}"                       # mbedtls_36 / mbedtls_42
        src_abs="$(pwd)/$ver/build/_deps/mbedtls-src"   # 必须在 cd 之前算好绝对路径
        if [[ -d "$src_abs" ]]; then
            (cd "$ex" && MBEDTLS_SRC="$src_abs" ./build.sh)
        else
            (cd "$ex" && ./build.sh)
        fi
        echo ""
    done
else
    echo ""
    echo ">>> [3/3] 跳过嵌入式示例（未找到 arm-none-eabi-gcc）"
    echo "    可单独构建：cd mbedtls_36/09_embedded_stm32 && ./build.sh"
fi

echo ""
echo "=============================================="
echo "  全部构建完成!"
echo "=============================================="
