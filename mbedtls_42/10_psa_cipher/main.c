/**
 * 示例10：PSA Crypto API - 对称加密 (Cipher)
 *
 * PSA Cipher API 提供分组密码和流密码的加密/解密操作。
 * 与 3.x 的 mbedtls_cipher_* API 不同，PSA API 将密钥作为参数传入，
 * 而不是通过 mbedtls_cipher_setup + mbedtls_cipher_setkey 分离设置。
 *
 * 4.x PSA Cipher API 关键变化（相比 3.x）：
 * - psa_cipher_encrypt_setup(&op, key, alg)  ← 直接传入密钥 ID
 * - psa_cipher_decrypt_setup(&op, key, alg)  ← 直接传入密钥 ID
 * - 不再需要 mbedtls_cipher_setkey() / mbedtls_cipher_set_iv() 分离调用
 *
 * 本示例演示：
 * - AES-256-CBC (PKCS7 填充)：最常用的对称加密模式
 * - AES-256-CTR：流式加密，适合实时数据
 * - 密钥生成、导入、导出、销毁的完整生命周期
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
 * 生成 AES-256 密钥
 *
 * PSA 密钥管理流程：
 * 1. 设置密钥属性（类型、长度、用途、算法）
 * 2. 调用 psa_generate_key() 生成密钥
 * 3. 返回的 key ID 用于后续操作
 * 4. 使用完毕后调用 psa_destroy_key() 销毁
 */
static int generate_aes_key(psa_key_id_t *key, psa_algorithm_t alg)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* 设置密钥用途：加密 + 解密 + 导出（psa_export_key 需要 EXPORT 标志） */
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_EXPORT);
    /* 设置允许的算法 */
    psa_set_key_algorithm(&attributes, alg);
    /* 设置密钥类型：AES */
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    /* 设置密钥长度：256 位 */
    psa_set_key_bits(&attributes, 256);

    psa_status_t status = psa_generate_key(&attributes, key);
    CHECK_PSA(status);
    printf("  AES-256 密钥已生成 (key_id=%u)\n", *key);
    return 0;
}

/**
 * 示例1：AES-256-CBC 加密/解密（PKCS7 填充）
 *
 * CBC 模式：每个明文块与前一个密文块异或后加密，提供一定混淆。
 * PKCS7 填充：当明文不是块大小的整数倍时，添加填充字节。
 * IV：初始化向量，每次加密应使用不同的 IV。
 */
static int example_aes_cbc_pkcs7(void)
{
    printf("\n=== 示例1: AES-256-CBC (PKCS7 填充) ===\n");

    psa_key_id_t key = 0;
    psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    /* 生成密钥 */
    if (generate_aes_key(&key, alg) != 0) {
        return -1;
    }

    const char *plaintext = "mbedTLS 4.x PSA Cipher API Demo!";
    size_t plaintext_len = strlen(plaintext);

    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES), /* 16 */
    };
    uint8_t iv[block_size];
    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;
    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    /* --- 加密 --- */
    psa_cipher_operation_t enc_op = PSA_CIPHER_OPERATION_INIT;

    /* 设置加密操作：传入密钥 ID + 算法 */
    psa_status_t status = psa_cipher_encrypt_setup(&enc_op, key, alg);
    CHECK_PSA(status);

    /* 生成随机 IV（CBC 模式必须） */
    size_t iv_len = 0;
    status = psa_cipher_generate_iv(&enc_op, iv, sizeof(iv), &iv_len);
    CHECK_PSA(status);
    print_hex("IV", iv, iv_len);

    /* 更新：传入明文，输出密文 */
    status = psa_cipher_update(&enc_op,
                               (const uint8_t *)plaintext, plaintext_len,
                               ciphertext, sizeof(ciphertext), &ciphertext_len);
    CHECK_PSA(status);

    /* 完成：处理最后的填充块 */
    size_t finish_len = 0;
    status = psa_cipher_finish(&enc_op,
                               ciphertext + ciphertext_len,
                               sizeof(ciphertext) - ciphertext_len,
                               &finish_len);
    CHECK_PSA(status);
    ciphertext_len += finish_len;

    print_hex("密文", ciphertext, ciphertext_len);
    printf("  明文长度: %zu, 密文长度: %zu (含填充)\n", plaintext_len, ciphertext_len);

    /* --- 解密 --- */
    psa_cipher_operation_t dec_op = PSA_CIPHER_OPERATION_INIT;

    status = psa_cipher_decrypt_setup(&dec_op, key, alg);
    CHECK_PSA(status);

    /* 设置 IV（必须与加密时相同） */
    status = psa_cipher_set_iv(&dec_op, iv, iv_len);
    CHECK_PSA(status);

    size_t dec_update_len = 0;
    status = psa_cipher_update(&dec_op, ciphertext, ciphertext_len,
                               decrypted, sizeof(decrypted), &dec_update_len);
    CHECK_PSA(status);

    size_t dec_finish_len = 0;
    status = psa_cipher_finish(&dec_op,
                               decrypted + dec_update_len,
                               sizeof(decrypted) - dec_update_len,
                               &dec_finish_len);
    CHECK_PSA(status);
    decrypted_len = dec_update_len + dec_finish_len;

    /* 验证解密结果 */
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("  ✓ 解密成功，与原文一致: \"%s\"\n", decrypted);
    } else {
        printf("  ✗ 解密结果不匹配!\n");
        psa_cipher_abort(&dec_op);
        psa_destroy_key(key);
        return -1;
    }

    psa_cipher_abort(&enc_op);
    psa_cipher_abort(&dec_op);
    psa_destroy_key(key);
    printf("  密钥已销毁\n");
    return 0;
}

/**
 * 示例2：AES-256-CTR 加密/解密
 *
 * CTR 模式：将分组密码转换为流密码，无需填充，适合流式数据。
 * 密文长度 = 明文长度（无填充开销）。
 */
static int example_aes_ctr(void)
{
    printf("\n=== 示例2: AES-256-CTR (无填充) ===\n");

    psa_key_id_t key = 0;
    psa_algorithm_t alg = PSA_ALG_CTR;

    if (generate_aes_key(&key, alg) != 0) {
        return -1;
    }

    const char *plaintext = "CTR mode: no padding needed!";
    size_t plaintext_len = strlen(plaintext);

    const size_t block_size = 16; /* AES block size */
    uint8_t iv[block_size];
    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;
    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    /* 加密 */
    psa_cipher_operation_t enc_op = PSA_CIPHER_OPERATION_INIT;
    psa_status_t status = psa_cipher_encrypt_setup(&enc_op, key, alg);
    CHECK_PSA(status);

    size_t iv_len = 0;
    status = psa_cipher_generate_iv(&enc_op, iv, sizeof(iv), &iv_len);
    CHECK_PSA(status);

    status = psa_cipher_update(&enc_op, (const uint8_t *)plaintext, plaintext_len,
                               ciphertext, sizeof(ciphertext), &ciphertext_len);
    CHECK_PSA(status);

    size_t finish_len = 0;
    status = psa_cipher_finish(&enc_op, ciphertext + ciphertext_len,
                               sizeof(ciphertext) - ciphertext_len, &finish_len);
    CHECK_PSA(status);
    ciphertext_len += finish_len;

    printf("  明文长度: %zu, 密文长度: %zu (CTR 无填充，长度相同)\n",
           plaintext_len, ciphertext_len);

    /* 解密 */
    psa_cipher_operation_t dec_op = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_decrypt_setup(&dec_op, key, alg);
    CHECK_PSA(status);
    status = psa_cipher_set_iv(&dec_op, iv, iv_len);
    CHECK_PSA(status);

    size_t dec_update_len = 0;
    status = psa_cipher_update(&dec_op, ciphertext, ciphertext_len,
                               decrypted, sizeof(decrypted), &dec_update_len);
    CHECK_PSA(status);

    size_t dec_finish_len = 0;
    status = psa_cipher_finish(&dec_op, decrypted + dec_update_len,
                               sizeof(decrypted) - dec_update_len, &dec_finish_len);
    CHECK_PSA(status);
    decrypted_len = dec_update_len + dec_finish_len;

    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("  ✓ CTR 解密成功\n");
    } else {
        printf("  ✗ CTR 解密失败!\n");
        return -1;
    }

    psa_cipher_abort(&enc_op);
    psa_cipher_abort(&dec_op);
    psa_destroy_key(key);
    return 0;
}

/**
 * 示例3：密钥导入与导出
 *
 * 演示如何从外部导入已有密钥，以及导出公钥/密钥材料。
 */
static int example_key_import_export(void)
{
    printf("\n=== 示例3: 密钥导入/导出 ===\n");

    /* 准备一个已知的 AES-256 密钥（32 字节） */
    uint8_t raw_key[32];
    memset(raw_key, 0x42, sizeof(raw_key)); /* 全部填充 0x42 */

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_PKCS7);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    /* 导入密钥 */
    psa_key_id_t key = 0;
    psa_status_t status = psa_import_key(&attributes, raw_key, sizeof(raw_key), &key);
    CHECK_PSA(status);
    printf("  密钥已导入 (key_id=%u)\n", key);

    /* 导出密钥（对称密钥直接导出原始字节） */
    uint8_t exported[32];
    size_t exported_len = 0;
    status = psa_export_key(key, exported, sizeof(exported), &exported_len);
    CHECK_PSA(status);

    if (memcmp(raw_key, exported, 32) == 0) {
        printf("  ✓ 导出的密钥与原始密钥一致\n");
    } else {
        printf("  ✗ 导出密钥不匹配!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* 查询密钥属性 */
    psa_key_attributes_t query_attrs = PSA_KEY_ATTRIBUTES_INIT;
    status = psa_get_key_attributes(key, &query_attrs);
    CHECK_PSA(status);
    printf("  密钥类型: 0x%04x (AES=%d)\n",
           (unsigned)psa_get_key_type(&query_attrs),
           psa_get_key_type(&query_attrs) == PSA_KEY_TYPE_AES);
    printf("  密钥长度: %zu bits\n", psa_get_key_bits(&query_attrs));

    psa_destroy_key(key);
    printf("  密钥已销毁\n");
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - 对称加密 (Cipher) ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_aes_cbc_pkcs7();
    ret |= example_aes_ctr();
    ret |= example_key_import_export();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
