/**
 * 示例09：PSA Crypto API - 哈希/摘要算法
 *
 * mbedTLS 4.x 推荐使用 PSA (Platform Security Architecture) Crypto API，
 * 它是统一的加密接口层，屏蔽了底层实现差异。
 *
 * PSA API 核心特点：
 * 1. 统一接口：所有算法通过 psa_algorithm_t 标识符选择
 * 2. 密钥管理：密钥由 PSA 密钥存储统一管理（psa_key_id_t）
 * 3. 硬件可替换：底层驱动可替换为硬件安全模块 (HSM)
 * 4. 策略控制：密钥使用策略在导入/生成时设定
 *
 * 本示例演示：
 * - psa_hash_compute()：一次性哈希计算
 * - psa_hash_setup/update/finish()：流式（多部分）哈希
 * - psa_hash_compare()：哈希比较验证
 *
 * 与 3.x 底层 API 对比：
 * | 功能         | 3.x (mbedtls/sha256.h)       | 4.x PSA (psa/crypto.h)           |
 * |-------------|-------------------------------|----------------------------------|
 * | SHA-256     | mbedtls_sha256()             | psa_hash_compute(PSA_ALG_SHA_256)|
 * | 流式哈希    | mbedtls_sha256_ret()         | psa_hash_setup/update/finish()   |
 * | 算法选择    | 编译时固定                    | 运行时通过 alg 参数选择          |
 */

#include <stdio.h>
#include <string.h>
#include "psa/crypto.h"

/* 辅助函数：打印十六进制 */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* 辅助宏：检查 PSA 状态码 */
#define CHECK_PSA(status) do { \
    if ((status) != PSA_SUCCESS) { \
        printf("  [ERROR] PSA error: %d at line %d\n", (int)(status), __LINE__); \
        return -1; \
    } \
} while(0)

/**
 * 示例1：一次性哈希计算 (psa_hash_compute)
 *
 * 适用于数据量较小、可以一次放入内存的场景。
 * PSA_ALG_SHA_256 / PSA_ALG_SHA_384 / PSA_ALG_SHA_512 等宏标识算法。
 */
static int example_psa_hash_compute(void)
{
    printf("\n=== 示例1: psa_hash_compute() 一次性哈希 ===\n");

    const char *message = "Hello, mbedTLS 4.x PSA!";
    size_t msg_len = strlen(message);

    /* SHA-256 */
    uint8_t hash_256[32];
    size_t hash_256_len = 0;
    printf("\n输入: \"%s\"\n", message);

    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
                                           (const uint8_t *)message, msg_len,
                                           hash_256, sizeof(hash_256),
                                           &hash_256_len);
    CHECK_PSA(status);
    print_hex("SHA-256", hash_256, hash_256_len);

    /* SHA-384 */
    uint8_t hash_384[48];
    size_t hash_384_len = 0;
    status = psa_hash_compute(PSA_ALG_SHA_384,
                              (const uint8_t *)message, msg_len,
                              hash_384, sizeof(hash_384),
                              &hash_384_len);
    CHECK_PSA(status);
    print_hex("SHA-384", hash_384, hash_384_len);

    /* SHA-512 */
    uint8_t hash_512[64];
    size_t hash_512_len = 0;
    status = psa_hash_compute(PSA_ALG_SHA_512,
                              (const uint8_t *)message, msg_len,
                              hash_512, sizeof(hash_512),
                              &hash_512_len);
    CHECK_PSA(status);
    print_hex("SHA-512", hash_512, hash_512_len);

    /* 验证：PSA_HASH_LENGTH 宏可以获取哈希输出长度 */
    printf("\n  PSA_HASH_LENGTH(PSA_ALG_SHA_256) = %d\n",
           (int)PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    printf("  PSA_HASH_LENGTH(PSA_ALG_SHA_384) = %d\n",
           (int)PSA_HASH_LENGTH(PSA_ALG_SHA_384));
    printf("  PSA_HASH_LENGTH(PSA_ALG_SHA_512) = %d\n",
           (int)PSA_HASH_LENGTH(PSA_ALG_SHA_512));

    return 0;
}

/**
 * 示例2：流式（多部分）哈希 (psa_hash_setup/update/finish)
 *
 * 适用于大文件分块处理，无需一次性加载全部数据到内存。
 * 操作对象 psa_hash_operation_t 维护内部状态。
 */
static int example_psa_hash_streaming(void)
{
    printf("\n=== 示例2: psa_hash_setup/update/finish() 流式哈希 ===\n");

    /* 模拟分块数据 */
    const char *chunks[] = { "Hello, ", "mbedTLS ", "4.x ", "PSA! " };
    size_t num_chunks = sizeof(chunks) / sizeof(chunks[0]);

    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    uint8_t hash[32];
    size_t hash_len = 0;

    printf("输入分块: ");
    for (size_t i = 0; i < num_chunks; i++) {
        printf("\"%s\"", chunks[i]);
    }
    printf("\n");

    /* 步骤1：初始化哈希操作，指定算法 */
    psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    CHECK_PSA(status);

    /* 步骤2：分块更新（可以调用任意多次） */
    for (size_t i = 0; i < num_chunks; i++) {
        status = psa_hash_update(&operation,
                                 (const uint8_t *)chunks[i],
                                 strlen(chunks[i]));
        CHECK_PSA(status);
    }

    /* 步骤3：完成计算，获取哈希值 */
    status = psa_hash_finish(&operation, hash, sizeof(hash), &hash_len);
    CHECK_PSA(status);

    print_hex("SHA-256 (流式)", hash, hash_len);

    /* 验证：与一次性计算结果一致 */
    uint8_t hash_ref[32];
    size_t hash_ref_len = 0;
    const char *full_msg = "Hello, mbedTLS 4.x PSA! ";
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              (const uint8_t *)full_msg, strlen(full_msg),
                              hash_ref, sizeof(hash_ref), &hash_ref_len);
    CHECK_PSA(status);

    if (memcmp(hash, hash_ref, hash_len) == 0) {
        printf("  ✓ 流式计算结果与一次性计算一致\n");
    } else {
        printf("  ✗ 结果不一致!\n");
        return -1;
    }

    return 0;
}

/**
 * 示例3：哈希比较验证 (psa_hash_compare)
 *
 * 用于验证数据完整性，例如校验文件下载后的哈希值。
 * 内部使用恒定时间比较，防止时序攻击。
 */
static int example_psa_hash_compare(void)
{
    printf("\n=== 示例3: psa_hash_compare() 哈希验证 ===\n");

    const char *message = "mbedTLS PSA integrity check";
    uint8_t expected_hash[32];
    size_t expected_len = 0;

    /* 先计算正确的哈希 */
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
                                           (const uint8_t *)message,
                                           strlen(message),
                                           expected_hash, sizeof(expected_hash),
                                           &expected_len);
    CHECK_PSA(status);

    /* 验证正确的哈希 */
    printf("输入: \"%s\"\n", message);
    status = psa_hash_compare(PSA_ALG_SHA_256,
                              (const uint8_t *)message, strlen(message),
                              expected_hash, expected_len);
    if (status == PSA_SUCCESS) {
        printf("  ✓ 哈希验证通过（数据完整）\n");
    } else {
        printf("  ✗ 哈希验证失败!\n");
        return -1;
    }

    /* 篡改数据后验证 */
    char tampered[] = "mbedTLS PSA integrity check";
    tampered[0] = 'M'; /* 修改第一个字符 */
    status = psa_hash_compare(PSA_ALG_SHA_256,
                              (const uint8_t *)tampered, strlen(tampered),
                              expected_hash, expected_len);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        printf("  ✓ 篡改检测成功（返回 PSA_ERROR_INVALID_SIGNATURE）\n");
    } else {
        printf("  ✗ 未检测到篡改!\n");
        return -1;
    }

    return 0;
}

/**
 * 示例4：哈希操作的中止 (psa_hash_abort)
 *
 * 当处理过程中发生错误时，需要调用 abort 释放资源。
 */
static int example_psa_hash_abort(void)
{
    printf("\n=== 示例4: psa_hash_abort() 中止操作 ===\n");

    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

    psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    CHECK_PSA(status);

    /* 模拟中途出错，中止操作 */
    const char *partial = "partial data";
    status = psa_hash_update(&operation, (const uint8_t *)partial,
                             strlen(partial));
    CHECK_PSA(status);

    /* 中止并释放资源 */
    status = psa_hash_abort(&operation);
    CHECK_PSA(status);
    printf("  ✓ 哈希操作已安全中止，资源已释放\n");

    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   mbedTLS 4.x PSA Crypto API - 哈希/摘要算法     ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    /* PSA 初始化（通常只需调用一次） */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[FATAL] psa_crypto_init() failed: %d\n", (int)status);
        return -1;
    }
    printf("PSA Crypto 子系统初始化成功\n");

    int ret = 0;
    ret |= example_psa_hash_compute();
    ret |= example_psa_hash_streaming();
    ret |= example_psa_hash_compare();
    ret |= example_psa_hash_abort();

    /* PSA 清理（程序退出前调用） */
    mbedtls_psa_crypto_free();

    printf("\n%s\n", ret == 0 ? "✓ 所有示例执行成功" : "✗ 部分示例失败");
    return ret;
}
