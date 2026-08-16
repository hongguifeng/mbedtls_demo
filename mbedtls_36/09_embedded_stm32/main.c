/**
 * @file    main.c
 * @brief   mbedTLS 3.6 + STM32F407 + FreeRTOS 嵌入式示例（Legacy API）
 *
 * 演示内容：
 *   1. 硬件初始化：USART1（日志）、STM32F4 硬件 RNG（熵源）
 *   2. mbedTLS 平台适配：注册 FreeRTOS 互斥锁（mbedtls_threading_set_alt）
 *   3. 三个 FreeRTOS 任务并发执行加密运算：
 *        - hash_task : SHA-256 哈希
 *        - aes_task  : AES-128-CBC 加解密往返
 *        - ecc_task  : ECDSA P-256 密钥生成 / 签名 / 验签
 *   4. 结果通过 USART1 打印（printf 已重定向到 hw_uart_putc）
 *
 * 每个任务持有独立的 entropy + ctr_drbg 上下文，避免共享随机数状态竞争。
 * mbedTLS 内部全局状态由 MBEDTLS_THREADING_C（FreeRTOS 互斥锁）保护。
 */

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include "stm32f4_hw.h"

/* 平台适配层（platform_glue.c）：注册 FreeRTOS 互斥锁回调 */
void mbedtls_platform_setup_threading(void);

/* =====================================================================
 * 工具函数
 * ===================================================================== */

/** 以十六进制打印一段字节 */
static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\r\n");
}

/** 打印 mbedTLS 错误码（便于定位）*/
static void print_mbedtls_error(const char *what, int ret)
{
    if (ret == 0) {
        return;
    }
    char errbuf[200];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    printf("[FAIL] %s: ret=-0x%04x (%s)\r\n", what, -ret, errbuf);
}

/* =====================================================================
 * 任务 1：SHA-256 哈希
 * ===================================================================== */
static void hash_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [hash_task] SHA-256 ---\r\n");

    const char *msg = "mbedtls on STM32F407 + FreeRTOS";
    unsigned char digest[32];

    int ret = mbedtls_sha256((const unsigned char *)msg, strlen(msg), digest, 0);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_sha256", ret);
    } else {
        print_hex("SHA-256: ", digest, 32);
    }

    vTaskDelete(NULL);
}

/* =====================================================================
 * 任务 2：AES-128-CBC 加解密往返
 * ===================================================================== */
static void aes_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [aes_task] AES-128-CBC ---\r\n");

    /* 16 字节密钥 + 16 字节 IV（教学用固定值；生产环境应随机生成）*/
    unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* 注意：CBC 无填充模式要求明文长度是块大小（16 字节）的整数倍 */
    const char *plaintext = "Hello, embedded!";   /* 恰好 16 字节 */
    size_t plen = strlen(plaintext);

    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    unsigned char iv_enc[16], iv_dec[16];
    memcpy(iv_enc, iv, 16);
    memcpy(iv_dec, iv, 16);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    if (ret == 0) {
        ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plen, iv_enc,
                                    (const unsigned char *)plaintext, ciphertext);
    }
    if (ret == 0) {
        print_hex("Ciphertext: ", ciphertext, plen);

        ret = mbedtls_aes_setkey_dec(&ctx, key, 128);
    }
    if (ret == 0) {
        ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, plen, iv_dec,
                                    ciphertext, decrypted);
    }
    if (ret == 0) {
        if (memcmp(decrypted, plaintext, plen) == 0) {
            printf("AES round-trip OK: %.*s\r\n", (int)plen, decrypted);
        } else {
            printf("[FAIL] AES round-trip mismatch\r\n");
        }
    } else {
        print_mbedtls_error("aes_crypt_cbc", ret);
    }

    mbedtls_aes_free(&ctx);
    vTaskDelete(NULL);
}

/* =====================================================================
 * 任务 3：ECDSA P-256 密钥生成 / 签名 / 验签
 * ===================================================================== */
static void ecc_task(void *arg)
{
    (void)arg;
    printf("\r\n--- [ecc_task] ECDSA P-256 ---\r\n");

    /* 本任务独立的随机数上下文（entropy + ctr_drbg）*/
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ecdsa_init(&ecdsa);

    const char *pers = "stm32-ecdsa-demo";
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        print_mbedtls_error("ctr_drbg_seed", ret);
        goto cleanup;
    }

    /* 1. 生成 P-256 密钥对 */
    ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        print_mbedtls_error("ecdsa_genkey", ret);
        goto cleanup;
    }
    printf("ECDSA P-256 keypair generated\r\n");

    /* 2. 对消息摘要签名 */
    const char *msg = "sign me";
    unsigned char hash[32];
    ret = mbedtls_sha256((const unsigned char *)msg, strlen(msg), hash, 0);
    if (ret != 0) {
        print_mbedtls_error("sha256", ret);
        goto cleanup;
    }

    unsigned char sig[512];
    size_t siglen = 0;
    /* 3.6 Legacy API：write_signature(ctx, md_alg, hash, hlen, sig, sig_size,
     *                                   &slen, f_rng, p_rng) */
    ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256,
                                        hash, sizeof(hash),
                                        sig, sizeof(sig), &siglen,
                                        mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        print_mbedtls_error("ecdsa_write_signature", ret);
        goto cleanup;
    }
    print_hex("Signature: ", sig, siglen);

    /* 3. 验签 */
    ret = mbedtls_ecdsa_read_signature(&ecdsa, hash, sizeof(hash), sig, siglen);
    if (ret != 0) {
        print_mbedtls_error("ecdsa_read_signature", ret);
    } else {
        printf("ECDSA verify OK\r\n");
    }

cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
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

    /* 关键：newlib 对非 TTY 的 stdout 默认全缓冲（4KB），裸机上缓冲区
     * 可能永远不刷新，导致串口看不到输出。这里设为无缓冲，printf 立即发送。*/
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\r\n========================================\r\n");
    printf(" mbedTLS 3.6 + STM32F407 + FreeRTOS\r\n");
    printf(" Legacy API embedded demo\r\n");
    printf("========================================\r\n");

    /* 2. 注册 FreeRTOS 互斥锁（mbedTLS 线程安全）*/
    mbedtls_platform_setup_threading();

    /* 3. 创建任务（每个任务内部自建随机数上下文）*/
    xTaskCreate(hash_task, "hash", 512, NULL, 2, NULL);
    xTaskCreate(aes_task,  "aes",  512, NULL, 2, NULL);
    xTaskCreate(ecc_task,  "ecc",  1024, NULL, 2, NULL);

    /* 4. 启动调度器 */
    vTaskStartScheduler();

    /* 不应到达这里 */
    for (;;) {
    }
}
