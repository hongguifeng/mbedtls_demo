/**
 * 示例11：PSA Crypto API - AEAD (认证加密)
 *
 * AEAD (Authenticated Encryption with Associated Data) 同时提供：
 * - 机密性：数据被加密，无法被窃听
 * - 完整性：数据被认证，无法被篡改
 * - 关联数据认证：附加数据（如头部、元数据）被认证但不加密
 *
 * 常用 AEAD 算法：
 * - AES-GCM：TLS 1.3 默认 AEAD，高性能
 * - ChaCha20-Poly1305：移动端/嵌入式推荐
 *
 * PSA AEAD API 特点：
 * - 一次性 API：psa_aead_encrypt() / psa_aead_decrypt()
 * - 多部分 API：psa_aead_encrypt_setup/update/finish()
 * - 密文格式：[ciphertext][tag]（标签附加在密文后面）
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
 * 生成 AES-256-GCM 密钥
 */
static int generate_gcm_key(psa_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    psa_status_t status = psa_generate_key(&attributes, key);
    CHECK_PSA(status);
    printf("  AES-256-GCM 密钥已生成 (key_id=%u)\n", *key);
    return 0;
}

/**
 * 示例1：AES-256-GCM 一次性加密/解密
 *
 * GCM 模式参数：
 * - nonce：96 位（12 字节）推荐长度，每次加密必须不同
 * - additional_data (AAD)：关联数据，被认证但不加密
 * - tag：128 位认证标签，附加在密文末尾
 */
static int example_gcm_one_shot(void)
{
    printf("\n=== 示例1: AES-256-GCM 一次性加密/解密 ===\n");

    psa_key_id_t key = 0;
    if (generate_gcm_key(&key) != 0) {
        return -1;
    }

    const char *plaintext = "Sensitive data: mbedTLS 4.x AEAD demo";
    size_t plaintext_len = strlen(plaintext);
    const char *aad = "header|version=1|";
    size_t aad_len = strlen(aad);

    /* GCM nonce：推荐 12 字节 (96 bits) */
    uint8_t nonce[12];
    psa_status_t status = psa_generate_random(nonce, sizeof(nonce));
    CHECK_PSA(status);
    print_hex("Nonce", nonce, sizeof(nonce));

    /* 密文缓冲区：明文长度 + 16 字节 tag */
    uint8_t ciphertext[256];
    size_t ciphertext_len = 0;

    /* --- 加密 --- */
    status = psa_aead_encrypt(key, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              (const uint8_t *)aad, aad_len,
                              (const uint8_t *)plaintext, plaintext_len,
                              ciphertext, sizeof(ciphertext),
                              &ciphertext_len);
    CHECK_PSA(status);

    print_hex("密文+Tag", ciphertext, ciphertext_len);
    printf("  明文长度: %zu, 密文+Tag 长度: %zu (含 16 字节 tag)\n",
           plaintext_len, ciphertext_len);

    /* --- 解密 --- */
    uint8_t decrypted[256];
    size_t decrypted_len = 0;

    status = psa_aead_decrypt(key, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              (const uint8_t *)aad, aad_len,
                              ciphertext, ciphertext_len,
                              decrypted, sizeof(decrypted),
                              &decrypted_len);
    CHECK_PSA(status);

    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("  ✓ GCM 解密成功，数据完整\n");
    } else {
        printf("  ✗ 解密结果不匹配!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* --- 篡改检测 --- */
    uint8_t tampered[256];
    memcpy(tampered, ciphertext, ciphertext_len);
    tampered[0] ^= 0xFF; /* 篡改密文第一个字节 */

    size_t tampered_dec_len = 0;
    status = psa_aead_decrypt(key, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              (const uint8_t *)aad, aad_len,
                              tampered, ciphertext_len,
                              decrypted, sizeof(decrypted),
                              &tampered_dec_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ 篡改检测成功（PSA_ERROR_INVALID_SIGNATURE）\n");
    } else {
        printf("  ✗ 未检测到篡改!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* --- AAD 不匹配检测 --- */
    const char *wrong_aad = "header|version=2|";
    size_t wrong_dec_len = 0;
    status = psa_aead_decrypt(key, PSA_ALG_GCM,
                              nonce, sizeof(nonce),
                              (const uint8_t *)wrong_aad, strlen(wrong_aad),
                              ciphertext, ciphertext_len,
                              decrypted, sizeof(decrypted),
                              &wrong_dec_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ AAD 不匹配检测成功\n");
    } else {
        printf("  ✗ AAD 篡改未检测到!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

/**
 * 示例2：AES-256-GCM 多部分（流式）加密/解密
 *
 * 适用于大数据量分块处理场景。
 * 流程：setup → set_nonce → set_additional_data → update(多次) → finish
 */
static int example_gcm_streaming(void)
{
    printf("\n=== 示例2: AES-256-GCM 多部分加密/解密 ===\n");

    psa_key_id_t key = 0;
    if (generate_gcm_key(&key) != 0) {
        return -1;
    }

    /* 模拟分块数据 */
    const char *chunks[] = { "Part 1: ", "Part 2: ", "Part 3: ", "Done!" };
    size_t num_chunks = sizeof(chunks) / sizeof(chunks[0]);
    size_t total_len = 0;
    for (size_t i = 0; i < num_chunks; i++) {
        total_len += strlen(chunks[i]);
    }

    uint8_t nonce[12];
    psa_status_t status = psa_generate_random(nonce, sizeof(nonce));
    CHECK_PSA(status);

    const char *aad = "streaming-aad";
    size_t aad_len = strlen(aad);

    /* --- 多部分加密 --- */
    uint8_t ciphertext[256];
    size_t ciphertext_len = 0;

    psa_aead_operation_t enc_op = PSA_AEAD_OPERATION_INIT;
    status = psa_aead_encrypt_setup(&enc_op, key, PSA_ALG_GCM);
    CHECK_PSA(status);

    status = psa_aead_set_nonce(&enc_op, nonce, sizeof(nonce));
    CHECK_PSA(status);

    status = psa_aead_update_ad(&enc_op,
                                (const uint8_t *)aad, aad_len);
    CHECK_PSA(status);

    /* 分块更新：psa_aead_update 的 *output_length 只返回本次调用的输出长度，
     * 必须用独立变量累加，不能直接复用 ciphertext_len（否则输出指针会错位） */
    for (size_t i = 0; i < num_chunks; i++) {
        size_t chunk_len = strlen(chunks[i]);
        size_t out_len = 0;
        status = psa_aead_update(&enc_op,
                                 (const uint8_t *)chunks[i], chunk_len,
                                 ciphertext + ciphertext_len,
                                 sizeof(ciphertext) - ciphertext_len,
                                 &out_len);
        CHECK_PSA(status);
        ciphertext_len += out_len;
    }

    /* 完成：输出最后的密文 + tag（4.x 中 tag 是独立参数） */
    uint8_t tag[16];
    size_t finish_len = 0;
    size_t tag_len = 0;
    status = psa_aead_finish(&enc_op,
                             ciphertext + ciphertext_len,
                             sizeof(ciphertext) - ciphertext_len,
                             &finish_len,
                             tag, sizeof(tag), &tag_len);
    CHECK_PSA(status);
    ciphertext_len += finish_len;
    memcpy(ciphertext + ciphertext_len, tag, tag_len);
    ciphertext_len += tag_len;

    printf("  明文总长度: %zu, 密文+Tag 长度: %zu\n", total_len, ciphertext_len);

    /* --- 多部分解密 --- */
    uint8_t decrypted[256];
    size_t decrypted_len = 0;

    psa_aead_operation_t dec_op = PSA_AEAD_OPERATION_INIT;
    status = psa_aead_decrypt_setup(&dec_op, key, PSA_ALG_GCM);
    CHECK_PSA(status);
    status = psa_aead_set_nonce(&dec_op, nonce, sizeof(nonce));
    CHECK_PSA(status);
    status = psa_aead_update_ad(&dec_op,
                                (const uint8_t *)aad, aad_len);
    CHECK_PSA(status);

    /* 分块解密（最后 16 字节是 tag，需要保留给 finish） */
    size_t data_only_len = ciphertext_len - 16;
    size_t dec_update_len = 0;
    status = psa_aead_update(&dec_op, ciphertext, data_only_len,
                             decrypted, sizeof(decrypted), &dec_update_len);
    CHECK_PSA(status);

    /* 解密完成：验证 tag（4.x 中用 psa_aead_verify） */
    size_t dec_finish_len = 0;
    status = psa_aead_verify(&dec_op,
                             decrypted + dec_update_len,
                             sizeof(decrypted) - dec_update_len,
                             &dec_finish_len,
                             ciphertext + data_only_len, 16);
    CHECK_PSA(status);
    decrypted_len = dec_update_len + dec_finish_len;

    /* 验证 */
    char full_plaintext[256];
    size_t offset = 0;
    for (size_t i = 0; i < num_chunks; i++) {
        size_t len = strlen(chunks[i]);
        memcpy(full_plaintext + offset, chunks[i], len);
        offset += len;
    }

    if (memcmp(full_plaintext, decrypted, total_len) == 0) {
        printf("  ✓ 流式 GCM 解密成功\n");
    } else {
        printf("  ✗ 流式解密结果不匹配!\n");
        psa_aead_abort(&enc_op);
        psa_aead_abort(&dec_op);
        psa_destroy_key(key);
        return -1;
    }

    psa_aead_abort(&enc_op);
    psa_aead_abort(&dec_op);
    psa_destroy_key(key);
    return 0;
}

/**
 * 示例3：GCM Tag 长度配置
 *
 * PSA_ALG_GCM 默认使用 16 字节 tag。
 * 可以使用 PSA_AEAD_TAG_LENGTH 宏指定不同 tag 长度（4-16 字节）。
 */
static int example_gcm_tag_length(void)
{
    printf("\n=== 示例3: GCM Tag 长度配置 ===\n");

    /* 使用 12 字节 tag（96 位）而非默认 16 字节 */
    psa_algorithm_t alg_12byte_tag = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 12);

    /* 密钥策略必须允许缩短的 tag 算法，否则加密时返回 NOT_PERMITTED */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg_12byte_tag);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);
    printf("  AES-256-GCM 密钥已生成（12 字节 tag, key_id=%u）\n", key);

    const char *plaintext = "Tag length test";
    size_t plaintext_len = strlen(plaintext);
    uint8_t nonce[12];
    status = psa_generate_random(nonce, sizeof(nonce));
    CHECK_PSA(status);

    uint8_t ciphertext[256];
    size_t ciphertext_len = 0;

    status = psa_aead_encrypt(key, alg_12byte_tag,
                              nonce, sizeof(nonce),
                              NULL, 0, /* 无 AAD */
                              (const uint8_t *)plaintext, plaintext_len,
                              ciphertext, sizeof(ciphertext),
                              &ciphertext_len);
    CHECK_PSA(status);

    printf("  明文长度: %zu, 密文+Tag 长度: %zu (12 字节 tag)\n",
           plaintext_len, ciphertext_len);
    printf("  预期: %zu + 12 = %zu\n", plaintext_len, plaintext_len + 12);

    /* 解密验证 */
    uint8_t decrypted[256];
    size_t decrypted_len = 0;
    status = psa_aead_decrypt(key, alg_12byte_tag,
                              nonce, sizeof(nonce),
                              NULL, 0,
                              ciphertext, ciphertext_len,
                              decrypted, sizeof(decrypted),
                              &decrypted_len);
    CHECK_PSA(status);

    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("  ✓ 12 字节 tag 解密成功\n");
    } else {
        printf("  ✗ 解密失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - AEAD (认证加密)   ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_gcm_one_shot();
    ret |= example_gcm_streaming();
    ret |= example_gcm_tag_length();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
