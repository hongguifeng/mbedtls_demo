/**
 * 示例01：哈希/摘要算法
 *
 * 本示例演示 mbedTLS 中常用的哈希算法：
 * - SHA-256：TLS 1.2/1.3 中最常用的哈希算法
 * - SHA-384：TLS 1.3 推荐
 * - SHA-512：更高安全强度
 *
 * 知识点：
 * 1. 哈希是单向函数，无法从输出反推输入
 * 2. 相同输入永远产生相同输出（确定性）
 * 3. 微小变化导致输出完全不同（雪崩效应）
 * 4. TLS 握手中使用哈希进行消息认证和密钥派生
 *
 * 在项目 task_mbedtls.c 中的体现：
 * - psa_crypto_init() 初始化 PSA 加密子系统（包括哈希引擎）
 * - TLS 握手内部使用 SHA-256/384 计算 Finished 消息
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"

/* 辅助函数：打印十六进制 */
static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * 示例1：使用底层 SHA-256 API
 * 适合流式处理大文件（分块 update）
 */
static int example_sha256_low_level(void)
{
    printf("\n=== 示例1: SHA-256 底层 API（流式处理）===\n");

    const char *message = "Hello, mbedTLS!";
    unsigned char hash[32]; /* SHA-256 输出固定 32 字节 (256 bits) */
    mbedtls_sha256_context ctx;

    printf("输入: \"%s\"\n", message);

    /* 初始化上下文 */
    mbedtls_sha256_init(&ctx);

    /* 开始计算，参数0表示SHA-256（1表示SHA-224） */
    mbedtls_sha256_starts(&ctx, 0);

    /* 可以多次 update（流式处理） */
    mbedtls_sha256_update(&ctx, (const unsigned char *)message, strlen(message));

    /* 获取最终结果 */
    mbedtls_sha256_finish(&ctx, hash);

    /* 清理 */
    mbedtls_sha256_free(&ctx);

    print_hex("SHA-256", hash, sizeof(hash));

    /* 验证：预计算的正确结果 */
    /* echo -n "Hello, mbedTLS!" | sha256sum */
    printf("验证: 可以用命令 'echo -n \"Hello, mbedTLS!\" | sha256sum' 对比\n");

    return 0;
}

/**
 * 示例2：使用通用 MD (Message Digest) API
 * 优点：可以通过名称/类型切换算法，不需要修改代码逻辑
 */
static int example_md_generic(void)
{
    printf("\n=== 示例2: 通用 MD API ===\n");

    const char *message = "Hello, mbedTLS!";
    unsigned char hash[64]; /* 足够容纳所有哈希算法的输出 */
    const mbedtls_md_info_t *md_info;
    size_t hash_len;

    /* 使用 SHA-256 */
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    hash_len = mbedtls_md_get_size(md_info);
    printf("算法: %s, 输出长度: %zu bytes\n", mbedtls_md_get_name(md_info), hash_len);

    /* 一次性计算（适合小数据） */
    mbedtls_md(md_info, (const unsigned char *)message, strlen(message), hash);
    print_hex("SHA-256", hash, hash_len);

    /* 使用 SHA-384 */
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    hash_len = mbedtls_md_get_size(md_info);
    printf("\n算法: %s, 输出长度: %zu bytes\n", mbedtls_md_get_name(md_info), hash_len);

    mbedtls_md(md_info, (const unsigned char *)message, strlen(message), hash);
    print_hex("SHA-384", hash, hash_len);

    /* 使用 SHA-512 */
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    hash_len = mbedtls_md_get_size(md_info);
    printf("\n算法: %s, 输出长度: %zu bytes\n", mbedtls_md_get_name(md_info), hash_len);

    mbedtls_md(md_info, (const unsigned char *)message, strlen(message), hash);
    print_hex("SHA-512", hash, hash_len);

    return 0;
}

/**
 * 示例3：演示哈希的雪崩效应
 * 即使只改变一个字符，输出也完全不同
 */
static int example_avalanche_effect(void)
{
    printf("\n=== 示例3: 雪崩效应演示 ===\n");

    const char *msg1 = "Hello, mbedTLS!";
    const char *msg2 = "Hello, mbedTLs!"; /* 只改了一个字符: S -> s */
    unsigned char hash1[32], hash2[32];
    int diff_bits = 0;

    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char *)msg1, strlen(msg1), hash1);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char *)msg2, strlen(msg2), hash2);

    printf("输入1: \"%s\"\n", msg1);
    print_hex("Hash1", hash1, 32);
    printf("输入2: \"%s\" (仅改变1个字符)\n", msg2);
    print_hex("Hash2", hash2, 32);

    /* 计算不同的 bit 数 */
    for (int i = 0; i < 32; i++) {
        unsigned char xor = hash1[i] ^ hash2[i];
        while (xor) {
            diff_bits += xor & 1;
            xor >>= 1;
        }
    }
    printf("不同的 bit 数: %d / 256 (约 %.1f%%)\n", diff_bits, diff_bits * 100.0 / 256);
    printf("理想情况下约 50%% 的 bit 不同，这就是雪崩效应\n");

    return 0;
}

/**
 * 示例4：HMAC (基于哈希的消息认证码)
 * HMAC = Hash(Key || message) 的安全变体
 * TLS 中用于：
 * - 消息完整性验证
 * - 密钥派生 (HKDF)
 */
static int example_hmac(void)
{
    printf("\n=== 示例4: HMAC-SHA256 ===\n");

    const char *message = "Hello, mbedTLS!";
    const unsigned char key[] = "my-secret-key-for-hmac";
    unsigned char hmac_output[32];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t ctx;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1); /* 1 = 启用 HMAC */
    mbedtls_md_hmac_starts(&ctx, key, sizeof(key) - 1);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)message, strlen(message));
    mbedtls_md_hmac_finish(&ctx, hmac_output);
    mbedtls_md_free(&ctx);

    printf("消息: \"%s\"\n", message);
    printf("密钥: \"%s\"\n", key);
    print_hex("HMAC-SHA256", hmac_output, 32);
    printf("\n说明: HMAC 需要密钥，只有持有相同密钥的双方才能验证消息完整性\n");
    printf("这与普通 Hash 的区别：攻击者无法在不知道密钥的情况下伪造 HMAC\n");

    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 01: 哈希/摘要算法           ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    example_sha256_low_level();
    example_md_generic();
    example_avalanche_effect();
    example_hmac();

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
