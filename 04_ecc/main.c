/**
 * 示例04：椭圆曲线密码学 (ECC)
 *
 * 本示例演示：
 * - ECC 密钥对生成 (P-256 / secp256r1)
 * - ECDSA 签名/验签
 * - ECDH 密钥交换（TLS 握手核心）
 *
 * 知识点：
 * 1. ECC 基于椭圆曲线离散对数问题
 * 2. 256-bit ECC ≈ 3072-bit RSA 安全性，但运算更快
 * 3. TLS 1.3 仅支持 ECDHE (Ephemeral) 密钥交换
 * 4. 常用曲线：
 *    - P-256 (secp256r1): TLS 最常用
 *    - P-384 (secp384r1): 更高安全性
 *    - X25519: TLS 1.3 推荐的密钥交换曲线
 *
 * 在项目 task_mbedtls.c 中的体现：
 * - mbedtls_pk_parse_key(&pkey_ext, ...) 解析 ECC 私钥
 * - mbedtls_pk_check_pair(&clicert_ext.pk, &pkey_ext, ...) 验证 ECC 密钥对
 * - TLS 握手中 ECDHE 密钥协商
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

/**
 * 示例1：ECC 密钥对生成 + ECDSA 签名
 *
 * ECDSA 用途（在 TLS 中）：
 * - 服务器证书签名
 * - 客户端证书签名（双向认证）
 * - CertificateVerify 消息
 */
static int example_ecdsa(mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例1: ECDSA 签名/验签 (P-256) ===\n");

    mbedtls_pk_context pk;
    unsigned char hash[32];
    unsigned char signature[128];
    size_t sig_len;
    int ret;

    const char *message = "TLS CertificateVerify message content";

    /* 生成 ECC P-256 密钥对 */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        printf("pk_setup 失败: -0x%04x\n", -ret);
        return ret;
    }

    printf("生成 P-256 (secp256r1) 密钥对...\n");
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(pk),
                              mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("密钥生成失败: -0x%04x\n", -ret);
        mbedtls_pk_free(&pk);
        return ret;
    }
    printf("✓ P-256 密钥对生成成功 (私钥: 32 bytes, 公钥: 65 bytes)\n");

    /* 导出公钥 */
    unsigned char pub_pem[512];
    ret = mbedtls_pk_write_pubkey_pem(&pk, pub_pem, sizeof(pub_pem));
    if (ret == 0) {
        printf("\nECC 公钥 (PEM):\n%s", pub_pem);
    }

    /* 计算消息哈希 */
    printf("消息: \"%s\"\n", message);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char *)message, strlen(message), hash);

    /* ECDSA 签名 */
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32,
                          signature, sizeof(signature), &sig_len,
                          mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("签名失败: -0x%04x\n", -ret);
        mbedtls_pk_free(&pk);
        return ret;
    }
    print_hex("ECDSA 签名 (DER)", signature, sig_len);
    printf("  注意: ECC 签名约 64-72 bytes，远小于 RSA 的 256 bytes\n");

    /* ECDSA 验签 */
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32,
                            signature, sig_len);
    if (ret == 0) {
        printf("✓ ECDSA 签名验证通过\n");
    } else {
        printf("✗ 验证失败: -0x%04x\n", -ret);
    }

    mbedtls_pk_free(&pk);
    return 0;
}

/**
 * 示例2：ECDH 密钥交换
 *
 * 这是 TLS 握手中最关键的步骤！
 * ECDHE (Ephemeral) 流程：
 * 1. 客户端生成临时 ECC 密钥对，发送公钥给服务器
 * 2. 服务器生成临时 ECC 密钥对，发送公钥给客户端
 * 3. 双方各自计算：共享密钥 = 自己的私钥 × 对方的公钥
 * 4. 数学保证双方得到相同的共享密钥
 * 5. 该共享密钥用于派生对称加密密钥
 *
 * 安全性：
 * - 即使攻击者截获两个公钥，也无法计算出共享密钥
 * - "Ephemeral" 表示每次连接使用新密钥对 → 前向安全 (PFS)
 */
static int example_ecdh(mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例2: ECDH 密钥交换 (TLS 握手核心) ===\n");
    printf("模拟 TLS 中客户端和服务器的密钥协商过程\n\n");

    mbedtls_ecdh_context ctx_client, ctx_server;
    unsigned char client_pub[66], server_pub[66]; /* TLS 格式: 1字节长度 + 65字节P-256未压缩公钥 */
    unsigned char client_secret[32], server_secret[32]; /* 共享密钥 */
    size_t client_pub_len, server_pub_len;
    size_t client_secret_len, server_secret_len;
    int ret;

    mbedtls_ecdh_init(&ctx_client);
    mbedtls_ecdh_init(&ctx_server);

    /* 设置曲线 */
    ret = mbedtls_ecdh_setup(&ctx_client, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) { printf("client setup 失败\n"); return ret; }
    ret = mbedtls_ecdh_setup(&ctx_server, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) { printf("server setup 失败\n"); return ret; }

    /* 步骤1: 客户端生成临时密钥对，导出公钥 */
    printf("步骤1: 客户端生成 ECDHE 密钥对...\n");
    ret = mbedtls_ecdh_make_public(&ctx_client, &client_pub_len,
                                   client_pub, sizeof(client_pub),
                                   mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) { printf("client make_public 失败: -0x%04x\n", -ret); return ret; }
    print_hex("  Client 公钥 (发送给 Server)", client_pub, client_pub_len);

    /* 步骤2: 服务器生成临时密钥对，导出公钥 */
    printf("\n步骤2: 服务器生成 ECDHE 密钥对...\n");
    ret = mbedtls_ecdh_make_public(&ctx_server, &server_pub_len,
                                   server_pub, sizeof(server_pub),
                                   mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) { printf("server make_public 失败: -0x%04x\n", -ret); return ret; }
    print_hex("  Server 公钥 (发送给 Client)", server_pub, server_pub_len);

    /* 步骤3: 双方读取对方公钥 */
    printf("\n步骤3: 交换公钥...\n");
    ret = mbedtls_ecdh_read_public(&ctx_client, server_pub, server_pub_len);
    if (ret != 0) { printf("client read_public 失败: -0x%04x\n", -ret); return ret; }
    ret = mbedtls_ecdh_read_public(&ctx_server, client_pub, client_pub_len);
    if (ret != 0) { printf("server read_public 失败: -0x%04x\n", -ret); return ret; }
    printf("  ✓ 公钥交换完成\n");

    /* 步骤4: 各自计算共享密钥 */
    printf("\n步骤4: 双方独立计算共享密钥...\n");
    ret = mbedtls_ecdh_calc_secret(&ctx_client, &client_secret_len,
                                   client_secret, sizeof(client_secret),
                                   mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) { printf("client calc_secret 失败: -0x%04x\n", -ret); return ret; }

    ret = mbedtls_ecdh_calc_secret(&ctx_server, &server_secret_len,
                                   server_secret, sizeof(server_secret),
                                   mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) { printf("server calc_secret 失败: -0x%04x\n", -ret); return ret; }

    print_hex("  Client 计算的共享密钥", client_secret, client_secret_len);
    print_hex("  Server 计算的共享密钥", server_secret, server_secret_len);

    /* 步骤5: 验证双方得到相同的共享密钥 */
    if (client_secret_len == server_secret_len &&
        memcmp(client_secret, server_secret, client_secret_len) == 0) {
        printf("\n✓ 双方共享密钥完全相同!\n");
        printf("  攻击者即使截获了双方的公钥，也无法计算出此密钥\n");
        printf("  此密钥将通过 HKDF 派生出 TLS 会话的对称加密密钥\n");
    } else {
        printf("\n✗ 共享密钥不匹配（不应该发生）\n");
        return -1;
    }

    mbedtls_ecdh_free(&ctx_client);
    mbedtls_ecdh_free(&ctx_server);
    return 0;
}

/**
 * 示例3：使用 PK 层解析 PEM 格式的 ECC 密钥
 * 这对应项目中 mbedtls_pk_parse_key() 的用法
 */
static int example_pk_ecc(mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例3: PK 层 ECC 密钥操作 ===\n");
    printf("对应项目中 mbedtls_pk_parse_key() 的用法\n\n");

    mbedtls_pk_context pk;
    int ret;

    /* 生成 ECC 密钥并导出为 PEM */
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
                        mbedtls_ctr_drbg_random, ctr_drbg);

    /* 导出私钥 PEM */
    unsigned char key_pem[2048];
    ret = mbedtls_pk_write_key_pem(&pk, key_pem, sizeof(key_pem));
    if (ret != 0) {
        printf("导出 PEM 失败: -0x%04x\n", -ret);
        mbedtls_pk_free(&pk);
        return ret;
    }
    printf("ECC 私钥 (PEM 格式):\n%s", key_pem);
    mbedtls_pk_free(&pk);

    /* 重新从 PEM 解析密钥 (模拟项目中从安全存储加载密钥) */
    printf("从 PEM 重新解析密钥 (模拟 MSCK_cert_and_priv_key_get)...\n");
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, key_pem, strlen((char *)key_pem) + 1,
                               NULL, 0,
                               mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("密钥解析失败: -0x%04x\n", -ret);
        mbedtls_pk_free(&pk);
        return ret;
    }

    printf("✓ 密钥解析成功\n");
    printf("  类型: %s\n", mbedtls_pk_get_name(&pk));
    printf("  位数: %zu bits\n", mbedtls_pk_get_bitlen(&pk));
    printf("  可用于签名: %s\n", mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA) ? "是" : "否");

    mbedtls_pk_free(&pk);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 04: 椭圆曲线密码学 (ECC)   ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret;

    const char *pers = "ecc_demo";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("RNG 初始化失败: -0x%04x\n", -ret);
        return 1;
    }

    example_ecdsa(&ctr_drbg);
    example_ecdh(&ctr_drbg);
    example_pk_ecc(&ctr_drbg);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("总结:\n");
    printf("  - ECDSA: 数字签名，用于证书和身份验证\n");
    printf("  - ECDH/ECDHE: 密钥交换，TLS 握手的核心\n");
    printf("  - P-256: TLS 中最常用的椭圆曲线\n");
    printf("  - 前向安全: 每次连接用新密钥对，历史会话不受影响\n");
    printf("  - 项目代码: mbedtls_pk_parse_key() 加载 ECC 私钥\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
