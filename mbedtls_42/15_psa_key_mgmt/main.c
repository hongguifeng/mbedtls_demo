/**
 * 示例15：PSA Crypto API - 密钥管理 (Key Management)
 *
 * PSA 密钥管理是 mbedTLS 4.x 的核心设计之一。
 * 所有密钥（对称/非对称）统一通过 psa_key_id_t 标识，
 * 由 PSA 密钥存储统一管理生命周期。
 *
 * 密钥生命周期：
 * 1. 创建：psa_generate_key() / psa_import_key()
 * 2. 使用：传入各操作函数（cipher/aead/mac/sign/...）
 * 3. 查询：psa_get_key_attributes()
 * 4. 导出：psa_export_key() / psa_export_public_key()
 * 5. 销毁：psa_destroy_key()
 *
 * 密钥属性 (psa_key_attributes_t)：
 * - type: 密钥类型（AES/RSA/ECC/HMAC/...）
 * - bits: 密钥长度（位）
 * - usage_flags: 允许的操作（ENCRYPT/DECRYPT/SIGN/VERIFY/DERIVE/...）
 * - algorithm: 允许的算法
 * - persistence: 持久化标识（可选）
 *
 * 安全设计：
 * - 密钥材料不直接暴露给应用层（通过 key_id 引用）
 * - 使用策略在创建时设定，运行时强制检查
 * - 支持硬件后端（HSM/SE），密钥可不出安全边界
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
 * 示例1：密钥生成与属性查询
 */
static int example_key_generation(void)
{
    printf("\n=== 示例1: 密钥生成与属性查询 ===\n");

    /* --- 生成 AES-256 密钥 --- */
    psa_key_attributes_t aes_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&aes_attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attrs, 256);
    psa_set_key_usage_flags(&aes_attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attrs, PSA_ALG_GCM);

    psa_key_id_t aes_key = 0;
    psa_status_t status = psa_generate_key(&aes_attrs, &aes_key);
    CHECK_PSA(status);
    printf("  AES-256 密钥生成 (key_id=%u)\n", aes_key);

    /* 查询属性 */
    psa_key_attributes_t query = PSA_KEY_ATTRIBUTES_INIT;
    status = psa_get_key_attributes(aes_key, &query);
    CHECK_PSA(status);
    printf("    类型: 0x%04x (AES=%d)\n",
           (unsigned)psa_get_key_type(&query),
           psa_get_key_type(&query) == PSA_KEY_TYPE_AES);
    printf("    长度: %zu bits\n", psa_get_key_bits(&query));
    printf("    用途: 0x%04x\n", (unsigned)psa_get_key_usage_flags(&query));

    /* --- 生成 HMAC-SHA256 密钥 --- */
    psa_key_attributes_t hmac_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&hmac_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&hmac_attrs, 256);
    psa_set_key_usage_flags(&hmac_attrs,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&hmac_attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t hmac_key = 0;
    status = psa_generate_key(&hmac_attrs, &hmac_key);
    CHECK_PSA(status);
    printf("  HMAC-SHA256 密钥生成 (key_id=%u)\n", hmac_key);

    /* --- 生成 ECC P-256 密钥对 --- */
    psa_key_attributes_t ecc_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ecc_attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&ecc_attrs, 256);
    psa_set_key_usage_flags(&ecc_attrs,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&ecc_attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t ecc_key = 0;
    status = psa_generate_key(&ecc_attrs, &ecc_key);
    CHECK_PSA(status);
    printf("  ECC P-256 密钥对生成 (key_id=%u)\n", ecc_key);

    /* 查询 ECC 属性 */
    query = psa_key_attributes_init();
    status = psa_get_key_attributes(ecc_key, &query);
    CHECK_PSA(status);
    printf("    类型: 0x%04x (ECC_KEY_PAIR=%d)\n",
           (unsigned)psa_get_key_type(&query),
           PSA_KEY_TYPE_IS_ECC_KEY_PAIR(psa_get_key_type(&query)));
    printf("    长度: %zu bits\n", psa_get_key_bits(&query));

    /* --- 生成 RSA-2048 密钥对 --- */
    psa_key_attributes_t rsa_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&rsa_attrs, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&rsa_attrs, 2048);
    psa_set_key_usage_flags(&rsa_attrs,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&rsa_attrs, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    psa_key_id_t rsa_key = 0;
    status = psa_generate_key(&rsa_attrs, &rsa_key);
    CHECK_PSA(status);
    printf("  RSA-2048 密钥对生成 (key_id=%u)\n", rsa_key);

    /* 清理 */
    psa_destroy_key(aes_key);
    psa_destroy_key(hmac_key);
    psa_destroy_key(ecc_key);
    psa_destroy_key(rsa_key);
    printf("  所有密钥已销毁\n");
    return 0;
}

/**
 * 示例2：密钥导入与导出
 */
static int example_key_import_export(void)
{
    printf("\n=== 示例2: 密钥导入与导出 ===\n");

    /* --- 导入 AES-128 密钥 --- */
    uint8_t raw_aes[16];
    for (int i = 0; i < 16; i++) raw_aes[i] = (uint8_t)(i * 17);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    psa_key_id_t key = 0;
    psa_status_t status = psa_import_key(&attrs, raw_aes, sizeof(raw_aes), &key);
    CHECK_PSA(status);
    printf("  AES-128 密钥导入 (key_id=%u)\n", key);

    /* 导出验证 */
    uint8_t exported[16];
    size_t exported_len = 0;
    status = psa_export_key(key, exported, sizeof(exported), &exported_len);
    CHECK_PSA(status);
    if (memcmp(raw_aes, exported, 16) == 0) {
        printf("  ✓ AES 密钥导出一致\n");
    } else {
        printf("  ✗ AES 密钥导出不一致!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* --- 导入 ECC P-256 私钥（原始格式：32 字节标量） --- */
    uint8_t ecc_private[32];
    for (int i = 0; i < 32; i++) ecc_private[i] = (uint8_t)(i + 1);

    psa_key_attributes_t ecc_attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ecc_attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&ecc_attrs, 256);
    psa_set_key_usage_flags(&ecc_attrs,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                            PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&ecc_attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t ecc_key = 0;
    status = psa_import_key(&ecc_attrs, ecc_private, sizeof(ecc_private), &ecc_key);
    CHECK_PSA(status);
    printf("  ECC P-256 私钥导入 (key_id=%u)\n", ecc_key);

    /* 导出公钥：P-256 未压缩点 0x04 + x(32) + y(32) = 65 字节 */
    uint8_t pub[65];
    size_t pub_len = 0;
    status = psa_export_public_key(ecc_key, pub, sizeof(pub), &pub_len);
    CHECK_PSA(status);
    print_hex("ECC 公钥", pub, pub_len);

    /* 导出私钥 */
    uint8_t priv_out[32];
    size_t priv_out_len = 0;
    status = psa_export_key(ecc_key, priv_out, sizeof(priv_out), &priv_out_len);
    CHECK_PSA(status);
    if (memcmp(ecc_private, priv_out, 32) == 0) {
        printf("  ✓ ECC 私钥导出一致\n");
    } else {
        printf("  ✗ ECC 私钥导出不一致!\n");
    }

    psa_destroy_key(key);
    psa_destroy_key(ecc_key);
    return 0;
}

/**
 * 示例3：密钥使用策略强制检查
 *
 * PSA 在运行时检查密钥是否允许指定操作。
 * 如果尝试用密钥执行未授权的操作，返回 PSA_ERROR_NOT_PERMITTED。
 */
static int example_key_policy_enforcement(void)
{
    printf("\n=== 示例3: 密钥使用策略强制检查 ===\n");

    /* 生成只允许加密的 AES 密钥 */
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT); /* 只允许加密！ */
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attrs, &key);
    CHECK_PSA(status);
    printf("  AES-256 密钥生成（仅允许加密）\n");

    /* 尝试解密 → 应该失败 */
    uint8_t iv[16] = {0};
    uint8_t ct[32] = {0};
    uint8_t pt[32];
    size_t pt_len = 0;

    psa_cipher_operation_t dec_op = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_decrypt_setup(&dec_op, key, PSA_ALG_CBC_PKCS7);
    if (status == PSA_ERROR_NOT_PERMITTED) {
        printf("  ✓ 解密被拒绝（PSA_ERROR_NOT_PERMITTED）\n");
    } else if (status == PSA_SUCCESS) {
        /* 某些实现可能在 update/finish 时才检查 */
        status = psa_cipher_set_iv(&dec_op, iv, sizeof(iv));
        if (status == PSA_ERROR_NOT_PERMITTED) {
            printf("  ✓ 解密被拒绝（set_iv 阶段）\n");
        } else {
            status = psa_cipher_update(&dec_op, ct, sizeof(ct), pt, sizeof(pt), &pt_len);
            if (status == PSA_ERROR_NOT_PERMITTED) {
                printf("  ✓ 解密被拒绝（update 阶段）\n");
            } else {
                printf("  [INFO] 此实现在 setup 阶段未检查策略\n");
            }
        }
        psa_cipher_abort(&dec_op);
    } else {
        printf("  [ERROR] 意外状态: %d\n", (int)status);
        psa_destroy_key(key);
        return -1;
    }

    /* 加密应该成功 */
    uint8_t pt_in[16] = "Encrypt me!";
    uint8_t ct_out[32];
    size_t ct_len = 0;

    psa_cipher_operation_t enc_op = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_encrypt_setup(&enc_op, key, PSA_ALG_CBC_PKCS7);
    CHECK_PSA(status);
    status = psa_cipher_set_iv(&enc_op, iv, sizeof(iv));
    CHECK_PSA(status);
    size_t update_len = 0;
    status = psa_cipher_update(&enc_op, pt_in, 16, ct_out, sizeof(ct_out), &update_len);
    CHECK_PSA(status);
    size_t finish_len = 0;
    status = psa_cipher_finish(&enc_op, ct_out + update_len,
                               sizeof(ct_out) - update_len, &finish_len);
    CHECK_PSA(status);
    printf("  ✓ 加密成功（策略允许）\n");

    psa_cipher_abort(&enc_op);
    psa_destroy_key(key);
    return 0;
}

/**
 * 示例4：密钥类型与算法兼容性检查
 */
static int example_key_algorithm_compatibility(void)
{
    printf("\n=== 示例4: 密钥类型与算法兼容性 ===\n");

    /* 生成 AES-256 密钥，只允许 GCM */
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM); /* 只允许 GCM */

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attrs, &key);
    CHECK_PSA(status);

    /* 尝试用 CBC 算法 → 应该失败 */
    uint8_t iv[16] = {0};
    uint8_t data[16] = "Test data!";
    uint8_t out[32];
    size_t out_len = 0;

    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_encrypt_setup(&op, key, PSA_ALG_CBC_PKCS7);
    if (status == PSA_ERROR_NOT_PERMITTED) {
        printf("  ✓ CBC 算法被拒绝（密钥只允许 GCM）\n");
    } else {
        printf("  [INFO] 此实现未在 setup 阶段检查算法兼容性\n");
        psa_cipher_abort(&op);
    }

    /* GCM 应该成功 */
    uint8_t nonce[12];
    psa_generate_random(nonce, sizeof(nonce));
    size_t gcm_ct_len = 0;
    status = psa_aead_encrypt(key, PSA_ALG_GCM, nonce, sizeof(nonce),
                              NULL, 0, data, 16, out, sizeof(out), &gcm_ct_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ GCM 算法成功（%zu 字节密文）\n", gcm_ct_len);
    } else {
        printf("  ✗ GCM 失败: %d\n", (int)status);
    }

    psa_destroy_key(key);
    return 0;
}

/**
 * 示例5：密钥 ID 空间说明
 *
 * PSA 密钥 ID 是 uint32_t，在单客户端模式下：
 * - key_id = 0: 无效/未使用
 * - key_id > 0: 有效密钥标识
 *
 * 在多客户端模式 (MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER) 下，
 * key_id 的高位编码了 owner（客户端）标识。
 */
static int example_key_id_space(void)
{
    printf("\n=== 示例5: 密钥 ID 空间 ===\n");

    /* 生成多个密钥，观察 ID 分配 */
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    psa_key_id_t keys[5];
    for (int i = 0; i < 5; i++) {
        psa_status_t status = psa_generate_key(&attrs, &keys[i]);
        CHECK_PSA(status);
        printf("  密钥 %d: key_id=%u\n", i, keys[i]);
    }

    /* 销毁中间一个，观察 ID 是否可复用 */
    psa_destroy_key(keys[2]);
    printf("  销毁密钥 2 (key_id=%u)\n", keys[2]);

    /* 生成新密钥，看是否复用已销毁的 ID */
    psa_key_id_t new_key = 0;
    psa_status_t status = psa_generate_key(&attrs, &new_key);
    CHECK_PSA(status);
    printf("  新生成密钥: key_id=%u %s\n", new_key,
           (new_key == keys[2]) ? "(复用了已销毁的 ID)" : "(新 ID)");

    /* 清理 */
    for (int i = 0; i < 5; i++) {
        if (i != 2) psa_destroy_key(keys[i]);
    }
    psa_destroy_key(new_key);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - 密钥管理          ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_key_generation();
    ret |= example_key_import_export();
    ret |= example_key_policy_enforcement();
    ret |= example_key_algorithm_compatibility();
    ret |= example_key_id_space();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
