#!/bin/bash
set -e

echo "=== 构建 mbedTLS 3.6 教程示例 ==="
echo ""

cd "$(dirname "$0")"

if [ ! -d build ]; then
    mkdir build
fi

cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

echo ""
echo "=== 构建完成! ==="
echo ""
echo "可运行的示例:"
echo "  ./build/01_hash        - 哈希/摘要算法"
echo "  ./build/02_aes         - 对称加密 (AES)"
echo "  ./build/03_rsa         - 非对称加密 (RSA)"
echo "  ./build/04_ecc         - 椭圆曲线密码学"
echo "  ./build/05_x509_parse  - X.509 证书解析"
echo "  ./build/06_tls_client  - TLS 客户端 (需要网络)"
echo "  ./build/07_tls_mutual  - TLS 双向认证 (本地)"
echo "  ./build/08_custom_bio  - 自定义 BIO (需要网络)"
