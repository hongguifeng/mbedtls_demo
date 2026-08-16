/**
 * @file    main.c
 * @brief   mbedTLS 4.2 + STM32F407 + FreeRTOS 嵌入式示例（PSA Crypto API）
 *
 * 与 3.6 示例（Legacy API）形成对照，演示 4.x 的 PSA 接口体系：
 *   1. 硬件初始化：USART1（日志）、STM32F4 硬件 RNG（熵源）
 *   2. mbedTLS 4.2 平台适配：
 *        - mbedtls_threading_set_alt()：9 个回调（互斥锁 + 条件变量）
 *        - mbedtls_platform_get_entropy()：驱动式熵源（硬件 RNG）
 *   3. 三个 FreeRTOS 任务并发执行 PSA 加密运算：
 *        - hash_task : psa_hash_compute(PSA_ALG_SHA_256)
 *        - aes_task  : psa_import_key + psa_cipher_encrypt/decrypt (AES-128-CBC)
 *        - ecc_task  : psa_generate_key(ECC P-256) + psa_sign_message / verify
 *   4. 结果通过 USART1 打印（printf 已重定向到 hw_uart_putc）
 *
 * PSA API 特点：
 *   - 密钥统一用 mbedtls_svc_key_id_t 句柄管理（psa_import_key / generate / destroy）
 *   - 算法用 psa_algorithm_t 编码（PSA_ALG_SHA_256、PSA_ALG_CBC_NO_PADDING、PSA_ALG_ECDSA(...)）
 *   - 不再需要手动管理 entropy/ctr_drbg 上下文：随机数由 PSA 内部
 *     通过 mbedtls_platform_get_entropy() 驱动获取
 */

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "psa/crypto.h"

#include "stm32f4_hw.h"

/* 平台适配层（platform_glue.c）：注册 FreeRTOS 互斥锁/条件变量回调 */
void mbedtls_platform_setup_threading(void);

/* =====================================================================
 * 工具函数
 * ===================================================================== */

/** 以十六进制打印一段字节 */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\r\n");
}

/** 打印 PSA 错误码（便于定位）。
 * 注意：4.2 移除了 psa_status_to_string()，这里用本地小函数替代。*/
static const char *psa_err_name(psa_status_t status)
{
    switch (status) {
        case PSA_SUCCESS:                    return "PSA_SUCCESS";
        case PSA_ERROR_GENERIC_ERROR:        return "PSA_ERROR_GENERIC_ERROR";
        case PSA_ERROR_NOT_SUPPORTED:        return "PSA_ERROR_NOT_SUPPORTED";
        case PSA_ERROR_NOT_PERMITTED:        return "PSA_ERROR_NOT_PERMITTED";
        case PSA_ERROR_BUFFER_TOO_SMALL:     return "PSA_ERROR_BUFFER_TOO_SMALL";
        case PSA_ERROR_ALREADY_EXISTS:       return "PSA_ERROR_ALREADY_EXISTS";
        case PSA_ERROR_DOES_NOT_EXIST:       return "PSA_ERROR_DOES_NOT_EXIST";
        case PSA_ERROR_BAD_STATE:            return "PSA_ERROR_BAD_STATE";
        case PSA_ERROR_INVALID_ARGUMENT:     return "PSA_ERROR_INVALID_ARGUMENT";
        case PSA_ERROR_INSUFFICIENT_MEMORY:  return "PSA_ERROR_INSUFFICIENT_MEMORY";
        case PSA_ERROR_INSUFFICIENT_STORAGE: return "PSA_ERROR_INSUFFICIENT_STORAGE";
        case PSA_ERROR_COMMUNICATION_FAILURE:return "PSA_ERROR_COMMUNICATION_FAILURE";
        case PSA_ERROR_STORAGE_FAILURE:      return "PSA_ERROR_STORAGE_FAILURE";
        case PSA_ERROR_HARDWARE_FAILURE:     return "PSA_ERROR_HARDWARE_FAILURE";
        case PSA_ERROR_CORRUPTION_DETECTED:  return "PSA_ERROR_CORRUPTION_DETECTED";
        case PSA_ERROR_INSUFFICIENT_ENTROPY: return "PSA_ERROR_INSUFFICIENT_ENTROPY";
        default:                             return "(unknown)";
    }
}

static void print_psa_error(const char *what, psa_status_t status)
{
    if (status == PSA_SUCCESS) {
        return;
    }
    printf("[FAIL] %s: -0x%04Lx (%s)\r\n", what,
           (unsigned long)(-status), psa_err_name(status));
}

/* =====================================================================
 * 任务 1：SHA-256 哈希（PSA）
 * ===================================================================== */
static void hash_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [hash_task] PSA SHA-256 ---\r\n");

    const char *msg = "mbedtls on STM32F407 + FreeRTOS";
    uint8_t digest[32];
    size_t digest_len = 0;

    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
                                           (const uint8_t *)msg, strlen(msg),
                                           digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_hash_compute", status);
    } else {
        print_hex("SHA-256: ", digest, digest_len);
    }

    vTaskDelete(NULL);
}

/* =====================================================================
 * 任务 2：AES-128-CBC 加解密往返（PSA）
 * ===================================================================== */
static void aes_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [aes_task] PSA AES-128-CBC ---\r\n");

    /* 16 字节密钥 + 16 字节 IV（教学用固定值；生产环境应随机生成）*/
    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* 注意：PSA_ALG_CBC_NO_PADDING 要求明文长度是块大小（16 字节）的整数倍 */
    const char *plaintext = "Hello, embedded!";   /* 恰好 16 字节 */
    size_t plen = strlen(plaintext);

    /* PSA 的 CBC 把 IV 作为"输入/输出"的一部分：
     *   加密输入 = IV || 明文，输出 = IV || 密文
     *   解密输入 = IV || 密文，输出 = IV || 明文 */
    uint8_t in_buf[16 + 64];
    uint8_t out_buf[16 + 64];
    memcpy(in_buf, iv, 16);
    memcpy(in_buf + 16, plaintext, plen);

    /* 1. 导入 AES 密钥（PSA 密钥句柄）*/
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    mbedtls_svc_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t status = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_import_key", status);
        vTaskDelete(NULL);
        return;
    }

    /* 2. 加密：输入 IV||明文，输出 IV||密文 */
    size_t out_len = 0;
    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING,
                                in_buf, 16 + plen,
                                out_buf, sizeof(out_buf), &out_len);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_cipher_encrypt", status);
        goto cleanup;
    }
    /* 密文 = 输出的后 plen 字节（前 16 字节是回显的 IV）*/
    print_hex("Ciphertext: ", out_buf + 16, out_len - 16);

    /* 3. 解密：输入 IV||密文，输出 IV||明文 */
    uint8_t dec_buf[16 + 64];
    size_t dec_len = 0;
    status = psa_cipher_decrypt(key_id, PSA_ALG_CBC_NO_PADDING,
                                out_buf, out_len,
                                dec_buf, sizeof(dec_buf), &dec_len);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_cipher_decrypt", status);
        goto cleanup;
    }
    /* 明文 = 输出的后 plen 字节 */
    if (dec_len >= 16 + plen &&
        memcmp(dec_buf + 16, plaintext, plen) == 0) {
        printf("AES round-trip OK: %.*s\r\n", (int)plen, dec_buf + 16);
    } else {
        printf("[FAIL] AES round-trip mismatch\r\n");
    }

cleanup:
    psa_destroy_key(key_id);
    vTaskDelete(NULL);
}

/* =====================================================================
 * 任务 3：ECDSA P-256 密钥生成 / 签名 / 验签（PSA）
 * ===================================================================== */
static void ecc_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [ecc_task] PSA ECDSA P-256 ---\r\n");

    /* 1. 生成 P-256 密钥对（PSA 内部自动从硬件 RNG 取随机数）*/
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);

    mbedtls_svc_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t status = psa_generate_key(&attrs, &key_id);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_generate_key", status);
        vTaskDelete(NULL);
        return;
    }
    printf("ECDSA P-256 keypair generated\r\n");

    /* 2. 对消息签名（PSA_ALG_ECDSA(PSA_ALG_SHA_256) = 纯 ECDSA，内部先哈希）*/
    const char *msg = "sign me";
    uint8_t sig[128];
    size_t sig_len = 0;

    status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                              (const uint8_t *)msg, strlen(msg),
                              sig, sizeof(sig), &sig_len);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_sign_message", status);
        goto cleanup;
    }
    print_hex("Signature: ", sig, sig_len);

    /* 3. 验签 */
    status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                (const uint8_t *)msg, strlen(msg),
                                sig, sig_len);
    if (status != PSA_SUCCESS) {
        print_psa_error("psa_verify_message", status);
    } else {
        printf("ECDSA verify OK\r\n");
    }

cleanup:
    psa_destroy_key(key_id);
    vTaskDelete(NULL);
}

/* =====================================================================
 * 主函数
 * ===================================================================== */
int main(void)
{
    /* 1. 硬件初始化 */
    hw_uart_init();
    hw_rng_init();

    /* newlib 对非 TTY 的 stdout 默认全缓冲（4KB），裸机上缓冲区
     * 可能永远不刷新。这里设为无缓冲，printf 立即发送。*/
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\r\n========================================\r\n");
    printf(" mbedTLS 4.2 + STM32F407 + FreeRTOS\r\n");
    printf(" PSA Crypto API embedded demo\r\n");
    printf("========================================\r\n");

    /* 2. 注册 FreeRTOS 互斥锁/条件变量（mbedTLS 线程安全）*/
    mbedtls_platform_setup_threading();

    /* 3. 创建任务 */
    xTaskCreate(hash_task, "hash", 512, NULL, 2, NULL);
    xTaskCreate(aes_task,  "aes",  512, NULL, 2, NULL);
    xTaskCreate(ecc_task,  "ecc",  1024, NULL, 2, NULL);

    /* 4. 启动调度器 */
    vTaskStartScheduler();

    /* 不应到达这里 */
    for (;;) {
    }
}
