/**
 * 示例12：PSA Crypto API - MAC (消息认证码)
 *
 * MAC 提供数据完整性认证（不加密），常用算法：
 * - HMAC-SHA256：基于哈希的 MAC，最广泛使用
 * - CMAC-AES：基于分组密码的 MAC，适合硬件加速
 *
 * PSA MAC API：
 * - 一次性：psa_mac_compute() / psa_mac_verify()
 * - 多部分：psa_mac_sign_setup/update/finish()
 *           psa_mac_verify_setup/update/finish()
 *
 * 密钥要求：
 * - HMAC 密钥类型：PSA_KEY_TYPE_HMAC
 * - CMAC 密钥类型：PSA_KEY_TYPE_AES（使用 PSA_ALG_CMAC）
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
 * 生成 HMAC-SHA256 密钥
 */
static int generate_hmac_key(psa_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, 256);

    psa_status_t status = psa_generate_key(&attributes, key);
    CHECK_PSA(status);
    printf("  HMAC-SHA256 密钥已生成 (key_id=%u)\n", *key);
    return 0;
}

/**
 * 示例1：HMAC-SHA256 一次性签名/验证
 */
static int example_hmac_one_shot(void)
{
    printf("\n=== 示例1: HMAC-SHA256 一次性签名/验证 ===\n");

    psa_key_id_t key = 0;
    if (generate_hmac_key(&key) != 0) {
        return -1;
    }

    const char *message = "mbedTLS PSA MAC demo message";
    size_t msg_len = strlen(message);
    psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);

    /* 签名 */
    uint8_t mac[32];
    size_t mac_len = 0;
    psa_status_t status = psa_mac_compute(key, alg,
                                          (const uint8_t *)message, msg_len,
                                          mac, sizeof(mac), &mac_len);
    CHECK_PSA(status);
    print_hex("HMAC-SHA256", mac, mac_len);

    /* 验证正确的 MAC */
    status = psa_mac_verify(key, alg,
                            (const uint8_t *)message, msg_len,
                            mac, mac_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ MAC 验证通过\n");
    } else {
        printf("  ✗ MAC 验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* 篡改消息后验证 */
    char tampered[] = "mbedTLS PSA MAC demo message";
    tampered[0] = 'X';
    status = psa_mac_verify(key, alg,
                            (const uint8_t *)tampered, strlen(tampered),
                            mac, mac_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ 篡改消息检测成功\n");
    } else {
        printf("  ✗ 未检测到篡改!\n");
        psa_destroy_key(key);
        return -1;
    }

    /* 篡改 MAC 后验证 */
    uint8_t bad_mac[32];
    memcpy(bad_mac, mac, mac_len);
    bad_mac[0] ^= 0xFF;
    status = psa_mac_verify(key, alg,
                            (const uint8_t *)message, msg_len,
                            bad_mac, mac_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ 篡改 MAC 检测成功\n");
    } else {
        printf("  ✗ 未检测到 MAC 篡改!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

/**
 * 示例2：HMAC-SHA256 多部分（流式）签名/验证
 */
static int example_hmac_streaming(void)
{
    printf("\n=== 示例2: HMAC-SHA256 多部分签名/验证 ===\n");

    psa_key_id_t key = 0;
    if (generate_hmac_key(&key) != 0) {
        return -1;
    }

    const char *chunks[] = { "Stream ", "part ", "1, ", "part ", "2" };
    size_t num_chunks = sizeof(chunks) / sizeof(chunks[0]);
    psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);

    /* 多部分签名 */
    uint8_t mac[32];
    size_t mac_len = 0;

    psa_mac_operation_t sign_op = PSA_MAC_OPERATION_INIT;
    psa_status_t status = psa_mac_sign_setup(&sign_op, key, alg);
    CHECK_PSA(status);

    for (size_t i = 0; i < num_chunks; i++) {
        status = psa_mac_update(&sign_op,
                                (const uint8_t *)chunks[i],
                                strlen(chunks[i]));
        CHECK_PSA(status);
    }

    status = psa_mac_sign_finish(&sign_op, mac, sizeof(mac), &mac_len);
    CHECK_PSA(status);
    print_hex("HMAC (流式)", mac, mac_len);

    /* 多部分验证 */
    psa_mac_operation_t verify_op = PSA_MAC_OPERATION_INIT;
    status = psa_mac_verify_setup(&verify_op, key, alg);
    CHECK_PSA(status);

    for (size_t i = 0; i < num_chunks; i++) {
        status = psa_mac_update(&verify_op,
                                (const uint8_t *)chunks[i],
                                strlen(chunks[i]));
        CHECK_PSA(status);
    }

    status = psa_mac_verify_finish(&verify_op, mac, mac_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ 流式 MAC 验证通过\n");
    } else {
        printf("  ✗ 流式 MAC 验证失败!\n");
        return -1;
    }

    psa_mac_abort(&sign_op);
    psa_mac_abort(&verify_op);
    psa_destroy_key(key);
    return 0;
}

/**
 * 示例3：AES-CMAC 签名/验证
 *
 * CMAC 基于 AES 分组密码，适合有硬件 AES 加速的场景。
 */
static int example_cmac(void)
{
    printf("\n=== 示例3: AES-256-CMAC ===\n");

    /* 生成 AES 密钥用于 CMAC */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    psa_key_id_t key = 0;
    psa_status_t status = psa_generate_key(&attributes, &key);
    CHECK_PSA(status);
    printf("  AES-256-CMAC 密钥已生成 (key_id=%u)\n", key);

    const char *message = "CMAC test message";
    size_t msg_len = strlen(message);

    /* CMAC 签名 */
    uint8_t mac[16]; /* CMAC-AES 输出固定 16 字节 */
    size_t mac_len = 0;
    status = psa_mac_compute(key, PSA_ALG_CMAC,
                             (const uint8_t *)message, msg_len,
                             mac, sizeof(mac), &mac_len);
    CHECK_PSA(status);
    print_hex("CMAC-AES256", mac, mac_len);

    /* CMAC 验证 */
    status = psa_mac_verify(key, PSA_ALG_CMAC,
                            (const uint8_t *)message, msg_len,
                            mac, mac_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ CMAC 验证通过\n");
    } else {
        printf("  ✗ CMAC 验证失败!\n");
        psa_destroy_key(key);
        return -1;
    }

    psa_destroy_key(key);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - MAC (消息认证码)  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_hmac_one_shot();
    ret |= example_hmac_streaming();
    ret |= example_cmac();

    mbedtls_psa_crypto_free();
    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
