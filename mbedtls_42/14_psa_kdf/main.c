/**
 * 示例14：PSA Crypto API - 密钥派生 (KDF) + 密钥协商 (Key Agreement)
 *
 * PSA 密钥派生 API 提供统一的 KDF 接口：
 * - HKDF (HMAC-based Key Derivation Function, RFC 5869)
 * - PBKDF2 (Password-Based Key Derivation Function)
 * - 其他算法（通过 psa_algorithm_t 标识）
 *
 * PSA 密钥协商 API：
 * - ECDH (Elliptic Curve Diffie-Hellman)
 * - 直接输出共享密钥，或作为 KDF 输入
 *
 * HKDF 流程（RFC 5869）：
 * 1. Extract: IKM + Salt → PRK (Pseudo-Random Key)
 * 2. Expand:  PRK + Info → OKM (Output Key Material)
 *
 * PSA HKDF 输入步骤：
 * - PSA_KEY_DERIVATION_INPUT_SALT   : 盐值（extract 阶段）
 * - PSA_KEY_DERIVATION_INPUT_SECRET : 输入密钥材料 IKM（extract 阶段）
 * - PSA_KEY_DERIVATION_INPUT_INFO   : 上下文信息 info（expand 阶段）
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
 * 示例1：HKDF-SHA256 密钥派生
 *
 * 从输入密钥材料 (IKM) 派生出固定长度的输出密钥。
 */
static int example_hkdf(void)
{
    printf("\n=== 示例1: HKDF-SHA256 密钥派生 ===\n");

    /* 输入密钥材料 (IKM) */
    const uint8_t ikm[] = "input keying material";
    size_t ikm_len = sizeof(ikm) - 1;

    /* 盐值 (Salt) */
    const uint8_t salt[] = "salt-value";
    size_t salt_len = sizeof(salt) - 1;

    /* 上下文信息 (Info) */
    const uint8_t info[] = "hmac-sha256 example";
    size_t info_len = sizeof(info) - 1;

    /* 期望输出长度：32 字节 (256 位) */
    enum { okm_len = 32 };
    uint8_t okm[okm_len];

    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_algorithm_t alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);

    /* 步骤1：初始化 HKDF 操作 */
    psa_status_t status = psa_key_derivation_setup(&operation, alg);
    CHECK_PSA(status);

    /* 步骤2：提供输入（顺序：SALT → SECRET → INFO） */

    /* 导入 IKM 为密钥对象（PSA 要求 secret 输入通过密钥传递） */
    psa_key_attributes_t ikm_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ikm_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&ikm_attrs, ikm_len * 8);
    psa_set_key_usage_flags(&ikm_attrs, PSA_KEY_USAGE_DERIVE);
    /* 密钥策略必须允许 HKDF 算法，否则 input_key 返回 NOT_PERMITTED */
    psa_set_key_algorithm(&ikm_attrs, alg);

    psa_key_id_t ikm_key = 0;
    status = psa_import_key(&ikm_attrs, ikm, ikm_len, &ikm_key);
    CHECK_PSA(status);

    /* 提供 Salt */
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    CHECK_PSA(status);

    /* 提供 IKM（通过密钥 ID） */
    status = psa_key_derivation_input_key(&operation,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          ikm_key);
    CHECK_PSA(status);

    /* 提供 Info */
    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, info_len);
    CHECK_PSA(status);

    /* 步骤3：输出派生密钥材料 */
    status = psa_key_derivation_output_bytes(&operation, okm, okm_len);
    CHECK_PSA(status);
    print_hex("HKDF 输出 (OKM)", okm, okm_len);

    /* 清理 */
    psa_key_derivation_abort(&operation);
    psa_destroy_key(ikm_key);

    /* 验证：使用 output_key 直接派生为 AES 密钥 */
    printf("\n  --- 派生为 AES-256 密钥 ---\n");
    psa_key_derivation_operation_t op2 = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op2, alg);
    CHECK_PSA(status);

    psa_key_attributes_t ikm_attrs2 = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ikm_attrs2, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&ikm_attrs2, ikm_len * 8);
    psa_set_key_usage_flags(&ikm_attrs2, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&ikm_attrs2, alg);
    psa_key_id_t ikm_key2 = 0;
    status = psa_import_key(&ikm_attrs2, ikm, ikm_len, &ikm_key2);
    CHECK_PSA(status);

    status = psa_key_derivation_input_bytes(&op2, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    CHECK_PSA(status);
    status = psa_key_derivation_input_key(&op2, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          ikm_key2);
    CHECK_PSA(status);
    status = psa_key_derivation_input_bytes(&op2, PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, info_len);
    CHECK_PSA(status);

    /* 直接输出为 AES-256 密钥 */
    psa_key_attributes_t aes_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&aes_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attrs, 256);
    psa_set_key_usage_flags(&aes_attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attrs, PSA_ALG_GCM);

    psa_key_id_t aes_key = 0;
    status = psa_key_derivation_output_key(&aes_attrs, &op2, &aes_key);
    CHECK_PSA(status);
    printf("  ✓ HKDF 派生出 AES-256-GCM 密钥 (key_id=%u)\n", aes_key);

    /* 验证派生的密钥可用于加密 */
    const char *test_data = "HKDF derived key test";
    uint8_t nonce[12];
    psa_generate_random(nonce, sizeof(nonce));
    uint8_t ct[128];
    size_t ct_len = 0;
    status = psa_aead_encrypt(aes_key, PSA_ALG_GCM, nonce, sizeof(nonce),
                              NULL, 0,
                              (const uint8_t *)test_data, strlen(test_data),
                              ct, sizeof(ct), &ct_len);
    CHECK_PSA(status);
    printf("  ✓ 派生密钥可用于 AES-GCM 加密 (%zu 字节密文)\n", ct_len);

    psa_key_derivation_abort(&op2);
    psa_destroy_key(ikm_key2);
    psa_destroy_key(aes_key);
    return 0;
}

/**
 * 示例2：ECDH 密钥协商 + HKDF 派生
 *
 * 完整流程：
 * 1. Alice 和 Bob 各自生成 ECC 密钥对
 * 2. 交换公钥
 * 3. 各自用对方公钥 + 自己私钥执行 ECDH → 共享秘密
 * 4. 用 HKDF 从共享秘密派生出对称密钥
 */
static int example_ecdh_hkdf(void)
{
    printf("\n=== 示例2: ECDH 密钥协商 + HKDF 派生 ===\n");

    /* --- Alice 生成 ECC P-256 密钥对 --- */
    psa_key_attributes_t alice_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&alice_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&alice_attrs, PSA_ALG_ECDH);
    psa_set_key_type(&alice_attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&alice_attrs, 256);

    psa_key_id_t alice_key = 0;
    psa_status_t status = psa_generate_key(&alice_attrs, &alice_key);
    CHECK_PSA(status);
    printf("  Alice ECC P-256 密钥对已生成\n");

    /* --- Bob 生成 ECC P-256 密钥对 --- */
    psa_key_attributes_t bob_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&bob_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&bob_attrs, PSA_ALG_ECDH);
    psa_set_key_type(&bob_attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&bob_attrs, 256);

    psa_key_id_t bob_key = 0;
    status = psa_generate_key(&bob_attrs, &bob_key);
    CHECK_PSA(status);
    printf("  Bob ECC P-256 密钥对已生成\n");

    /* --- 交换公钥 --- */
    uint8_t alice_pub[65], bob_pub[65]; /* P-256 未压缩点：0x04 + x(32) + y(32) = 65 字节 */
    size_t alice_pub_len = 0, bob_pub_len = 0;
    status = psa_export_public_key(alice_key, alice_pub, sizeof(alice_pub), &alice_pub_len);
    CHECK_PSA(status);
    status = psa_export_public_key(bob_key, bob_pub, sizeof(bob_pub), &bob_pub_len);
    CHECK_PSA(status);
    printf("  公钥交换完成 (各 %zu 字节)\n", alice_pub_len);

    /* --- Alice 执行 ECDH：用自己的私钥 + Bob 的公钥 --- */
    psa_key_attributes_t shared_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&shared_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&shared_attrs, 256);
    /* DERIVE 用于后续 HKDF 派生，EXPORT 用于导出共享秘密做一致性验证 */
    psa_set_key_usage_flags(&shared_attrs,
                            PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    /* 共享秘密将作为 HKDF 的输入密钥，策略必须允许 HKDF 算法 */
    psa_set_key_algorithm(&shared_attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    psa_key_id_t alice_shared = 0;
    status = psa_key_agreement(alice_key, bob_pub, bob_pub_len,
                               PSA_ALG_ECDH, &shared_attrs, &alice_shared);
    CHECK_PSA(status);
    printf("  Alice ECDH 共享秘密已计算 (key_id=%u)\n", alice_shared);

    /* --- Bob 执行 ECDH：用自己的私钥 + Alice 的公钥 --- */
    psa_key_id_t bob_shared = 0;
    status = psa_key_agreement(bob_key, alice_pub, alice_pub_len,
                               PSA_ALG_ECDH, &shared_attrs, &bob_shared);
    CHECK_PSA(status);
    printf("  Bob ECDH 共享秘密已计算 (key_id=%u)\n", bob_shared);

    /* --- 验证双方共享秘密一致 --- */
    uint8_t alice_secret[32], bob_secret[32];
    size_t alice_secret_len = 0, bob_secret_len = 0;
    status = psa_export_key(alice_shared, alice_secret, sizeof(alice_secret), &alice_secret_len);
    CHECK_PSA(status);
    status = psa_export_key(bob_shared, bob_secret, sizeof(bob_secret), &bob_secret_len);
    CHECK_PSA(status);

    if (memcmp(alice_secret, bob_secret, 32) == 0) {
        printf("  ✓ Alice 和 Bob 的共享秘密一致\n");
    } else {
        printf("  ✗ 共享秘密不一致!\n");
        psa_destroy_key(alice_shared);
        psa_destroy_key(bob_shared);
        psa_destroy_key(alice_key);
        psa_destroy_key(bob_key);
        return -1;
    }

    /* --- 用 HKDF 从共享秘密派生 AES-256-GCM 密钥 --- */
    const uint8_t info[] = "tls-key-material";
    size_t info_len = sizeof(info) - 1;

    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    CHECK_PSA(status);

    /* 无 salt（使用默认零值） */
    status = psa_key_derivation_input_bytes(&kdf_op,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            NULL, 0);
    CHECK_PSA(status);

    /* 共享秘密作为 IKM */
    status = psa_key_derivation_input_key(&kdf_op,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          alice_shared);
    CHECK_PSA(status);

    /* Info */
    status = psa_key_derivation_input_bytes(&kdf_op,
                                            PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, info_len);
    CHECK_PSA(status);

    /* 派生 AES-256-GCM 密钥 */
    psa_key_attributes_t aes_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&aes_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attrs, 256);
    psa_set_key_usage_flags(&aes_attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attrs, PSA_ALG_GCM);

    psa_key_id_t session_key = 0;
    status = psa_key_derivation_output_key(&aes_attrs, &kdf_op, &session_key);
    CHECK_PSA(status);
    printf("  ✓ HKDF 派生出会话 AES-256-GCM 密钥 (key_id=%u)\n", session_key);

    /* --- 用会话密钥加密/解密验证 --- */
    const char *msg = "Secure session message!";
    uint8_t nonce[12];
    psa_generate_random(nonce, sizeof(nonce));
    uint8_t ct[128], pt[128];
    size_t ct_len = 0, pt_len = 0;

    status = psa_aead_encrypt(session_key, PSA_ALG_GCM, nonce, sizeof(nonce),
                              NULL, 0, (const uint8_t *)msg, strlen(msg),
                              ct, sizeof(ct), &ct_len);
    CHECK_PSA(status);
    status = psa_aead_decrypt(session_key, PSA_ALG_GCM, nonce, sizeof(nonce),
                              NULL, 0, ct, ct_len, pt, sizeof(pt), &pt_len);
    CHECK_PSA(status);

    if (memcmp(msg, pt, strlen(msg)) == 0) {
        printf("  ✓ 会话密钥加密/解密验证通过\n");
    } else {
        printf("  ✗ 会话密钥验证失败!\n");
    }

    /* 清理 */
    psa_key_derivation_abort(&kdf_op);
    psa_destroy_key(session_key);
    psa_destroy_key(alice_shared);
    psa_destroy_key(bob_shared);
    psa_destroy_key(alice_key);
    psa_destroy_key(bob_key);
    return 0;
}

/**
 * 示例3：HKDF-Extract（仅 extract 阶段）
 *
 * 只执行 HKDF 的 extract 步骤，输出 PRK。
 */
static int example_hkdf_extract(void)
{
    printf("\n=== 示例3: HKDF-Extract (仅 Extract 阶段) ===\n");

    const uint8_t ikm[] = "extract-only-ikm";
    size_t ikm_len = sizeof(ikm) - 1;
    const uint8_t salt[] = "extract-salt";
    size_t salt_len = sizeof(salt) - 1;

    uint8_t prk[32]; /* PRK 长度 = 哈希输出长度 */
    size_t prk_len = 0;

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    CHECK_PSA(status);

    /* 导入 IKM */
    psa_key_attributes_t ikm_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ikm_attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&ikm_attrs, ikm_len * 8);
    psa_set_key_usage_flags(&ikm_attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&ikm_attrs, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    psa_key_id_t ikm_key = 0;
    status = psa_import_key(&ikm_attrs, ikm, ikm_len, &ikm_key);
    CHECK_PSA(status);

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    CHECK_PSA(status);
    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
    CHECK_PSA(status);

    /* 输出 PRK */
    status = psa_key_derivation_output_bytes(&op, prk, sizeof(prk));
    CHECK_PSA(status);
    print_hex("PRK (HMAC-SHA256)", prk, 32);

    psa_key_derivation_abort(&op);
    psa_destroy_key(ikm_key);
    printf("  ✓ HKDF-Extract 完成\n");
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - KDF + Key Agree. ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_hkdf();
    ret |= example_ecdh_hkdf();
    ret |= example_hkdf_extract();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
