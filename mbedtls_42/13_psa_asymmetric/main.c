/**
 * 示例13：PSA Crypto API - 非对称加密 (ECC/RSA)
 *
 * PSA 非对称操作包括：
 * - 签名/验证：psa_sign_message / psa_verify_message（消息签名）
 *              psa_sign_hash / psa_verify_hash（哈希签名）
 * - 加密/解密：psa_asymmetric_encrypt / psa_asymmetric_decrypt
 *
 * ECC 曲线在 PSA 中的表示：
 * - 密钥类型 = PSA_KEY_TYPE_ECC_KEY_PAIR(family)
 * - family: PSA_ECC_FAMILY_SECP_R1 (NIST P-256/P-384), PSA_ECC_FAMILY_MONTGOMERY (X25519)
 * - 曲线大小通过 psa_set_key_bits() 指定（256/384/521）
 *
 * 注意：PSA 中 ECC 曲线由 family + bits 组合确定，
 *       而非 3.x 中的 MBEDTLS_ECP_DP_SECP256R1_ENABLED 等编译宏。
 */

#include <stdio.h>
#include <string.h>
#include "psa/crypto.h"

#define CHECK_PSA(status) do { \
    if ((status) != PSA_SUCCESS) { \
        printf("  [ERROR] PSA error: %d at line %d\n", (int)(status), __LINE__); \
        return -1; \
    } \
} while(0)

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * 示例1：ECC P-256 密钥生成 + ECDSA 签名/验证
 *
 * ECDSA (Elliptic Curve Digital Signature Algorithm)：
 * - 签名算法：PSA_ALG_ECDSA(PSA_ALG_SHA_256)
 * - 密钥类型：PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), bits=256
 */
static int example_ecc_ecdsa(void)
{
    printf("\n=== 示例1: ECC P-256 ECDSA 签名/验证 ===\n");

    /* --- 生成 ECC P-256 密钥对 --- */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    /* ECC 密钥类型：SECP_R1 族（NIST 曲线） */
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    /* 曲线大小：256 位 → P-256 (secp256r1) */
    psa_set_key_bits(&attributes, 256);

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);
    printf("  ECC P-256 密钥对已生成 (key_id=%u)\n", key);

    /* --- 导出公钥 --- */
    uint8_t pub_key[65]; /* P-256 公钥：0x04 + x(32) + y(32) = 65 字节（未压缩点格式） */
    size_t pub_key_len = 0;
    status = psa_export_public_key(key, pub_key, sizeof(pub_key), &pub_key_len);
    CHECK_PSA(status);
    print_hex("ECC 公钥", pub_key, pub_key_len);

    /* --- ECDSA 签名（消息签名，内部先哈希再签名） --- */
    const char *message = "mbedTLS 4.x ECC ECDSA signature demo";
    size_t msg_len = strlen(message);

    uint8_t signature[128]; /* ECDSA P-256 签名最大 64 字节 (r,s) */
    size_t sig_len = 0;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

    status = psa_sign_message(key, alg,
                              (const uint8_t *)message, msg_len,
                              signature, sizeof(signature), &sig_len);
    CHECK_PSA(status);
    print_hex("ECDSA 签名", signature, sig_len);

    /* --- ECDSA 验证（使用密钥对中的公钥） --- */
    status = psa_verify_message(key, alg,
                                (const uint8_t *)message, msg_len,
                                signature, sig_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ ECDSA 签名验证通过\n");
    } else {
        printf("  ✗ ECDSA 验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* --- 使用独立公钥验证 --- */
    /* 导入公钥为独立密钥 */
    psa_key_attributes_t pub_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&pub_attrs, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&pub_attrs, alg);
    psa_set_key_type(&pub_attrs,
                     PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&pub_attrs, 256);

    psa_key_id_t pub_key_id = 0;
    status = psa_import_key(&pub_attrs, pub_key, pub_key_len, &pub_key_id);
    CHECK_PSA(status);

    status = psa_verify_message(pub_key_id, alg,
                                (const uint8_t *)message, msg_len,
                                signature, sig_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ 独立公钥验证通过\n");
    } else {
        printf("  ✗ 独立公钥验证失败!\n");
        psa_destroy_key(pub_key_id);
        psa_destroy_key(key);
        return -1;
    }

    /* --- 篡改检测 --- */
    char tampered[] = "mbedTLS 4.x ECC ECDSA signature demo";
    tampered[0] = 'X';
    status = psa_verify_message(pub_key_id, alg,
                                (const uint8_t *)tampered, strlen(tampered),
                                signature, sig_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ 篡改消息检测成功\n");
    } else {
        printf("  ✗ 未检测到篡改!\n");
        psa_destroy_key(pub_key_id);
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(pub_key_id);
    psa_destroy_key(key);
    return 0;
}

/**
 * 示例2：ECC P-384 ECDSA（更高安全强度）
 */
static int example_ecc_p384(void)
{
    printf("\n=== 示例2: ECC P-384 ECDSA ===\n");

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_384));
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 384); /* P-384 (secp384r1) */

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);
    printf("  ECC P-384 密钥对已生成 (key_id=%u)\n", key);

    /* 导出公钥：P-384 公钥 0x04 + x(48) + y(48) = 97 字节（未压缩点格式） */
    uint8_t pub_key[97];
    size_t pub_key_len = 0;
    status = psa_export_public_key(key, pub_key, sizeof(pub_key), &pub_key_len);
    CHECK_PSA(status);
    printf("  公钥长度: %zu 字节\n", pub_key_len);

    /* 签名 */
    const char *message = "P-384 ECDSA test";
    uint8_t signature[128];
    size_t sig_len = 0;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384);

    status = psa_sign_message(key, alg,
                              (const uint8_t *)message, strlen(message),
                              signature, sizeof(signature), &sig_len);
    CHECK_PSA(status);
    printf("  签名长度: %zu 字节\n", sig_len);

    /* 验证 */
    status = psa_verify_message(key, alg,
                                (const uint8_t *)message, strlen(message),
                                signature, sig_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ P-384 ECDSA 验证通过\n");
    } else {
        printf("  ✗ P-384 ECDSA 验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

/**
 * 示例3：RSA-2048 PKCS#1 v1.5 签名/验证
 */
static int example_rsa_sign(void)
{
    printf("\n=== 示例3: RSA-2048 PKCS#1 v1.5 签名/验证 ===\n");

    /* 生成 RSA-2048 密钥对 */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, 2048);

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);
    printf("  RSA-2048 密钥对已生成 (key_id=%u)\n", key);

    /* 导出公钥 */
    uint8_t pub_key[512];
    size_t pub_key_len = 0;
    status = psa_export_public_key(key, pub_key, sizeof(pub_key), &pub_key_len);
    CHECK_PSA(status);
    printf("  RSA 公钥长度: %zu 字节\n", pub_key_len);

    /* RSA PKCS#1 v1.5 签名 */
    const char *message = "RSA PKCS1 v1.5 signature test";
    uint8_t signature[256]; /* RSA-2048 签名最大 256 字节 */
    size_t sig_len = 0;
    psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);

    status = psa_sign_message(key, alg,
                              (const uint8_t *)message, strlen(message),
                              signature, sizeof(signature), &sig_len);
    CHECK_PSA(status);
    printf("  RSA 签名长度: %zu 字节\n", sig_len);

    /* 验证 */
    status = psa_verify_message(key, alg,
                                (const uint8_t *)message, strlen(message),
                                signature, sig_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ RSA 签名验证通过\n");
    } else {
        printf("  ✗ RSA 签名验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* 篡改检测 */
    char tampered[] = "RSA PKCS1 v1.5 signature test";
    tampered[0] = 'X';
    status = psa_verify_message(key, alg,
                                (const uint8_t *)tampered, strlen(tampered),
                                signature, sig_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ RSA 篡改检测成功\n");
    } else {
        printf("  ✗ RSA 篡改未检测到!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

/**
 * 示例4：psa_sign_hash / psa_verify_hash（先哈希再签名）
 *
 * 适用于需要手动控制哈希过程的场景，例如：
 * - 流式数据：先分块计算哈希，再对哈希值签名
 * - 跨语言互操作：确保哈希算法一致
 */
static int example_sign_hash(void)
{
    printf("\n=== 示例4: psa_sign_hash / psa_verify_hash ===\n");

    /* 生成 ECC P-256 密钥 */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);

    /* 手动计算哈希 */
    const char *message = "Manual hash then sign";
    uint8_t hash[32];
    size_t hash_len = 0;
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              (const uint8_t *)message, strlen(message),
                              hash, sizeof(hash), &hash_len);
    CHECK_PSA(status);
    print_hex("SHA-256 哈希", hash, hash_len);

    /* 对哈希值签名 */
    uint8_t signature[128];
    size_t sig_len = 0;
    psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

    status = psa_sign_hash(key, alg, hash, hash_len,
                           signature, sizeof(signature), &sig_len);
    CHECK_PSA(status);
    printf("  ECDSA 签名长度: %zu 字节\n", sig_len);

    /* 验证哈希签名 */
    status = psa_verify_hash(key, alg, hash, hash_len,
                             signature, sig_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ sign_hash/verify_hash 验证通过\n");
    } else {
        printf("  ✗ sign_hash/verify_hash 验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - 非对称加密        ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_ecc_ecdsa();
    ret |= example_ecc_p384();
    ret |= example_rsa_sign();
    ret |= example_sign_hash();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
