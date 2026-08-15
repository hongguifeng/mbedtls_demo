/**
 * 示例03：非对称加密 (RSA)
 *
 * 本示例演示：
 * - RSA 密钥对生成
 * - RSA 加密/解密（OAEP 填充）
 * - RSA 签名/验签（PSS 填充）
 *
 * 知识点：
 * 1. RSA 基于大整数分解难题
 * 2. 公钥 (n, e) 用于加密和验签
 * 3. 私钥 (n, d) 用于解密和签名
 * 4. RSA 运算较慢，通常只用于：
 *    - 加密少量数据（如会话密钥）
 *    - 数字签名（签摘要而非原文）
 * 5. TLS 中 RSA 的用途：
 *    - 证书中包含 RSA 公钥
 *    - 服务器用 RSA 私钥签名（证明身份）
 *    - TLS 1.2 可选 RSA 密钥交换（TLS 1.3 已禁用）
 *
 * 在项目 task_mbedtls.c 中的体现：
 * - mbedtls_pk_parse_key() 解析私钥
 * - mbedtls_pk_check_pair() 验证证书与私钥匹配
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

/* 初始化随机数生成器 */
static int init_rng(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg)
{
    const char *pers = "rsa_demo";
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    return mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                 (const unsigned char *)pers, strlen(pers));
}

/**
 * 示例1：RSA 密钥对生成
 */
static int example_rsa_keygen(mbedtls_pk_context *pk,
                              mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例1: RSA-2048 密钥对生成 ===\n");
    int ret;

    mbedtls_pk_init(pk);
    ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        printf("pk_setup 失败: -0x%04x\n", -ret);
        return ret;
    }

    printf("正在生成 RSA-2048 密钥对（可能需要几秒钟）...\n");
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random,
                              ctr_drbg, 2048, 65537);
    if (ret != 0) {
        printf("密钥生成失败: -0x%04x\n", -ret);
        return ret;
    }

    printf("✓ RSA-2048 密钥对生成成功\n");
    printf("  密钥长度: 2048 bits\n");
    printf("  公钥指数 e: 65537 (0x10001)\n");
    printf("  应用: TLS 证书签名、身份验证\n");

    /* 导出公钥 PEM */
    unsigned char pub_pem[1024];
    ret = mbedtls_pk_write_pubkey_pem(pk, pub_pem, sizeof(pub_pem));
    if (ret == 0) {
        printf("\n公钥 (PEM 格式):\n%s", pub_pem);
    }

    return 0;
}

/**
 * 示例2：RSA 加密/解密 (OAEP 填充)
 *
 * OAEP (Optimal Asymmetric Encryption Padding) 比 PKCS#1 v1.5 更安全
 * 注意：RSA 加密的数据量有限 (密钥长度 - padding开销)
 * 实际中通常只用 RSA 加密对称密钥（混合加密）
 */
static int example_rsa_encrypt(mbedtls_pk_context *pk,
                               mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例2: RSA-OAEP 加密/解密 ===\n");

    const char *plaintext = "Secret session key material"; /* 实际中这里是 AES 密钥 */
    unsigned char ciphertext[256]; /* RSA-2048 输出 256 字节 */
    unsigned char decrypted[256];
    size_t olen;
    int ret;

    printf("明文: \"%s\" (%zu bytes)\n", plaintext, strlen(plaintext));
    printf("说明: 实际 TLS 中，RSA 加密的是会话密钥（几十字节），不是大量数据\n\n");

    /* 用公钥加密 */
    ret = mbedtls_pk_encrypt(pk, (const unsigned char *)plaintext, strlen(plaintext),
                             ciphertext, &olen, sizeof(ciphertext),
                             mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("加密失败: -0x%04x\n", -ret);
        return ret;
    }
    print_hex("密文", ciphertext, olen);

    /* 用私钥解密 */
    ret = mbedtls_pk_decrypt(pk, ciphertext, olen,
                             decrypted, &olen, sizeof(decrypted),
                             mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("解密失败: -0x%04x\n", -ret);
        return ret;
    }
    decrypted[olen] = '\0';
    printf("解密: \"%s\"\n", decrypted);

    if (memcmp(plaintext, decrypted, strlen(plaintext)) == 0) {
        printf("✓ RSA 加密/解密验证通过\n");
    } else {
        printf("✗ 验证失败!\n");
        return -1;
    }

    return 0;
}

/**
 * 示例3：RSA 数字签名 (PSS 填充)
 *
 * 数字签名流程：
 * 1. 发送方：Hash(消息) → 用私钥签名 → 得到签名值
 * 2. 接收方：Hash(消息) → 用公钥验签 → 确认是否匹配
 *
 * 这正是 TLS 握手中服务器证明身份的方式：
 * - 服务器用私钥对握手消息签名
 * - 客户端用证书中的公钥验证签名
 */
static int example_rsa_sign(mbedtls_pk_context *pk,
                            mbedtls_ctr_drbg_context *ctr_drbg)
{
    printf("\n=== 示例3: RSA-PSS 数字签名 ===\n");

    const char *message = "This message is signed by the server's private key";
    unsigned char hash[32];
    unsigned char signature[256];
    size_t sig_len;
    int ret;

    printf("消息: \"%s\"\n", message);

    /* 步骤1：计算消息的 SHA-256 哈希 */
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char *)message, strlen(message), hash);
    print_hex("SHA-256 摘要", hash, 32);

    /* 步骤2：用私钥对哈希签名 */
    ret = mbedtls_pk_sign(pk, MBEDTLS_MD_SHA256, hash, 32,
                          signature, sizeof(signature), &sig_len,
                          mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("签名失败: -0x%04x\n", -ret);
        return ret;
    }
    print_hex("签名值", signature, sig_len);

    /* 步骤3：用公钥验证签名 */
    ret = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, 32,
                            signature, sig_len);
    if (ret == 0) {
        printf("✓ 签名验证通过 —— 确认消息来自私钥持有者\n");
    } else {
        printf("✗ 签名验证失败: -0x%04x\n", -ret);
        return ret;
    }

    /* 演示篡改检测 */
    printf("\n--- 演示篡改检测 ---\n");
    hash[0] ^= 0x01; /* 模拟消息被篡改（哈希不同） */
    ret = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, 32,
                            signature, sig_len);
    if (ret != 0) {
        printf("✓ 检测到篡改! 签名验证失败 (ret = -0x%04x)\n", -ret);
        printf("  消息被修改后签名不再匹配\n");
    }

    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 03: 非对称加密 (RSA)       ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    int ret;

    /* 初始化随机数生成器 */
    ret = init_rng(&entropy, &ctr_drbg);
    if (ret != 0) {
        printf("RNG 初始化失败: -0x%04x\n", -ret);
        return 1;
    }

    /* 运行示例 */
    ret = example_rsa_keygen(&pk, &ctr_drbg);
    if (ret == 0) ret = example_rsa_encrypt(&pk, &ctr_drbg);
    if (ret == 0) ret = example_rsa_sign(&pk, &ctr_drbg);

    /* 清理 */
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("总结:\n");
    printf("  - RSA 密钥生成: mbedtls_rsa_gen_key()\n");
    printf("  - RSA 加密: mbedtls_pk_encrypt() (公钥加密)\n");
    printf("  - RSA 解密: mbedtls_pk_decrypt() (私钥解密)\n");
    printf("  - RSA 签名: mbedtls_pk_sign() (私钥签名)\n");
    printf("  - RSA 验签: mbedtls_pk_verify() (公钥验签)\n");
    printf("  - TLS 中 RSA 主要用于证书签名和身份验证\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
