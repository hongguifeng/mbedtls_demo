#!/bin/bash
set -e

echo "=== 构建 mbedTLS 4.2 PSA Crypto API 教程示例 ==="
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
echo "  ./build/09_psa_hash        - PSA 哈希/摘要"
echo "  ./build/10_psa_cipher      - PSA 对称加密 (AES-CBC/CTR)"
echo "  ./build/11_psa_aead        - PSA AEAD (AES-GCM)"
echo "  ./build/12_psa_mac         - PSA MAC (HMAC/CMAC)"
echo "  ./build/13_psa_asymmetric  - PSA 非对称 (ECC/RSA 签名)"
echo "  ./build/14_psa_kdf         - PSA KDF (HKDF/ECDH)"
echo "  ./build/15_psa_key_mgmt    - PSA 密钥管理"
