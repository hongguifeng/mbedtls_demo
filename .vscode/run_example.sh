#!/bin/bash
# 交互式选择并运行 mbedTLS 教程示例
# 用法: 直接运行（在 VS Code 任务 "Run Example (select)" 中调用），
#       或传入编号/名称直接运行: ./run_example.sh 11  或  ./run_example.sh 11_psa_aead

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 编号|可执行文件相对路径|工作目录|说明
EXAMPLES=(
    "01|mbedtls_36/build/01_hash|mbedtls_36|哈希/摘要算法"
    "02|mbedtls_36/build/02_aes|mbedtls_36|对称加密 (AES)"
    "03|mbedtls_36/build/03_rsa|mbedtls_36|非对称加密 (RSA)"
    "04|mbedtls_36/build/04_ecc|mbedtls_36|椭圆曲线密码学"
    "05|mbedtls_36/build/05_x509_parse|mbedtls_36|X.509 证书解析"
    "06|mbedtls_36/build/06_tls_client|mbedtls_36|TLS 客户端 (需要网络)"
    "07|mbedtls_36/build/07_tls_mutual|mbedtls_36|TLS 双向认证 (本地)"
    "08|mbedtls_36/build/08_custom_bio|mbedtls_36|自定义 BIO (需要网络)"
    "09|mbedtls_42/build/09_psa_hash|mbedtls_42|PSA 哈希/摘要"
    "10|mbedtls_42/build/10_psa_cipher|mbedtls_42|PSA 对称加密 (AES-CBC/CTR)"
    "11|mbedtls_42/build/11_psa_aead|mbedtls_42|PSA AEAD (AES-GCM)"
    "12|mbedtls_42/build/12_psa_mac|mbedtls_42|PSA MAC (HMAC/CMAC)"
    "13|mbedtls_42/build/13_psa_asymmetric|mbedtls_42|PSA 非对称 (ECC/RSA 签名)"
    "14|mbedtls_42/build/14_psa_kdf|mbedtls_42|PSA KDF (HKDF/ECDH)"
    "15|mbedtls_42/build/15_psa_key_mgmt|mbedtls_42|PSA 密钥管理"
)

run_example() {
    local entry="${EXAMPLES[$1]}"
    local num bin dir desc
    IFS='|' read -r num bin dir desc <<< "$entry"
    local exe="$ROOT/$bin"

    if [ ! -x "$exe" ]; then
        echo "错误: $exe 不存在或不可执行，请先构建 (Build $num 或 Build All)"
        return 1
    fi

    echo ""
    echo "=============================================="
    echo "  运行示例 $num: $desc"
    echo "=============================================="
    echo ""
    (cd "$ROOT/$dir" && "$exe")
    local rc=$?
    echo ""
    if [ $rc -eq 0 ]; then
        echo ">>> 示例 $num 执行成功"
    else
        echo ">>> 示例 $num 执行失败 (exit code: $rc)"
    fi
    return $rc
}

# 支持直接传参: 编号 (11) 或名称 (11_psa_aead)
if [ -n "$1" ]; then
    for i in "${!EXAMPLES[@]}"; do
        entry="${EXAMPLES[$i]}"
        IFS='|' read -r num bin dir desc <<< "$entry"
        if [ "$1" = "$num" ] || [ "$1" = "$(basename "$bin")" ]; then
            run_example "$i"
            exit $?
        fi
    done
    echo "错误: 未知示例 '$1' (可用编号 01-15 或名称如 11_psa_aead)"
    exit 1
fi

# 交互菜单
while true; do
    echo ""
    echo "================ mbedTLS 教程示例 ================"
    echo "  [mbedtls_36] Legacy API"
    for i in 0 1 2 3 4 5 6 7; do
        IFS='|' read -r num bin dir desc <<< "${EXAMPLES[$i]}"
        printf "   %2s  %-18s %s\n" "$num" "$(basename "$bin")" "$desc"
    done
    echo "  [mbedtls_42] PSA Crypto API"
    for i in 8 9 10 11 12 13 14; do
        IFS='|' read -r num bin dir desc <<< "${EXAMPLES[$i]}"
        printf "   %2s  %-18s %s\n" "$num" "$(basename "$bin")" "$desc"
    done
    echo "   --  00  退出"
    echo "=============================================="
    printf "请选择示例编号 (00-15): "
    read -r choice
    case "$choice" in
        00|"") exit 0 ;;
        01|02|03|04|05|06|07|08|09|10|11|12|13|14|15)
            run_example "$((10#$choice - 1))"
            ;;
        *) echo "无效输入: $choice" ;;
    esac
done
