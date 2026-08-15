#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=============================================="
echo "  mbedTLS 教程 - 总构建脚本"
echo "=============================================="
echo ""

# Build mbedTLS 3.6 sub-project
echo ">>> [1/2] 构建 mbedtls_36 (mbedTLS 3.6.0 LTS)"
echo ""
cd mbedtls_36
./build.sh
cd ..

echo ""
echo ">>> [2/2] 构建 mbedtls_42 (mbedTLS 4.2.0 PSA Crypto)"
echo ""
cd mbedtls_42
./build.sh
cd ..

echo ""
echo "=============================================="
echo "  全部构建完成!"
echo "=============================================="
