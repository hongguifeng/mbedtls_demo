/**
 * 示例02：对称加密 (AES)
 *
 * 本示例演示：
 * - AES-CBC 模式：需要 padding，不提供完整性保护
 * - AES-GCM 模式：AEAD 模式，同时提供加密和认证（TLS 首选）
 * - AES-CTR 模式：流密码模式
 *
 * 知识点：
 * 1. 对称加密使用同一密钥进行加密和解密
 * 2. AES 密钥长度: 128/192/256 bit
 * 3. 加密模式决定了安全特性：
 *    - CBC: 需要 IV，需要 padding，不提供认证
 *    - GCM: 需要 IV/Nonce，提供 AEAD（认证加密）
 *    - CTR: 需要 Nonce，将块密码转为流密码
 * 4. TLS 1.2/1.3 使用 AES-GCM 或 AES-CCM 作为数据加密
 *
 * 在 TLS 中的位置：
 * - 握手完成后，双方协商出对称密钥
 * - 所有应用数据使用该密钥通过 AES-GCM 加密
 * - 每条记录使用不同的 IV (隐式序号 + 固定部分)
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * 示例1：AES-CBC 模式
 * - 经典的分组加密模式
 * - 需要 16 字节对齐（PKCS7 padding）
 * - 不提供完整性保护
 */
static int example_aes_cbc(void)
{
    printf("\n=== 示例1: AES-256-CBC 加密/解密 ===\n");

    /* 256-bit 密钥 (32 bytes) */
    unsigned char key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    /* IV: 初始化向量，16 字节，每次加密必须不同！ */
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char iv_dec[16];

    /* 明文必须是 16 字节的整数倍（这里手动对齐） */
    const char *plaintext = "AES-CBC Example!"; /* 刚好 16 字节 */
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    mbedtls_aes_context aes;

    printf("明文: \"%s\" (%zu bytes)\n", plaintext, strlen(plaintext));
    print_hex("密钥", key, 32);
    print_hex("IV  ", iv, 16);

    /* 加密 */
    memcpy(iv_dec, iv, 16); /* 保存 IV 副本用于解密 */
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16,
                          iv, (const unsigned char *)plaintext, ciphertext);
    mbedtls_aes_free(&aes);

    print_hex("密文", ciphertext, 16);

    /* 解密 */
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16,
                          iv_dec, ciphertext, decrypted);
    mbedtls_aes_free(&aes);

    printf("解密: \"%.*s\"\n", 16, decrypted);

    /* 验证 */
    if (memcmp(plaintext, decrypted, 16) == 0) {
        printf("✓ 加密/解密验证通过\n");
    } else {
        printf("✗ 验证失败!\n");
        return -1;
    }

    return 0;
}

/**
 * 示例2：AES-GCM 模式 (AEAD - Authenticated Encryption with Associated Data)
 *
 * GCM 是 TLS 中最重要的加密模式：
 * - 同时提供加密（机密性）和认证（完整性）
 * - 支持 AAD（关联数据）：不加密但需要认证的数据（如 TLS 记录头）
 * - 产生 Authentication Tag：任何篡改都会导致验证失败
 *
 * TLS 记录格式：
 * ┌─────────────────────┬──────────────────────────────────┬─────────────┐
 * │  Record Header (AAD)│  Encrypted Payload               │  Auth Tag   │
 * │  (明文,需要认证)     │  (密文)                          │  (16 bytes) │
 * └─────────────────────┴──────────────────────────────────┴─────────────┘
 */
static int example_aes_gcm(void)
{
    printf("\n=== 示例2: AES-256-GCM (AEAD) ===\n");
    printf("这是 TLS 中最常用的加密模式\n\n");

    unsigned char key[32] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    /* Nonce/IV: GCM 推荐 12 字节 */
    unsigned char nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    /* 明文 */
    const char *plaintext = "This is secret data protected by AES-GCM in TLS!";
    size_t plaintext_len = strlen(plaintext);

    /* AAD: 关联数据（类似 TLS 记录头，不加密但需要认证） */
    const unsigned char aad[] = {0x17, 0x03, 0x03, 0x00, 0x35}; /* TLS record header 示例 */

    unsigned char ciphertext[128];
    unsigned char tag[16]; /* 认证标签 */
    unsigned char decrypted[128];
    int ret;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);

    printf("明文: \"%s\" (%zu bytes)\n", plaintext, plaintext_len);
    print_hex("密钥 ", key, 32);
    print_hex("Nonce", nonce, 12);
    print_hex("AAD  ", aad, sizeof(aad));

    /* 加密 + 生成认证标签 */
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                    plaintext_len,
                                    nonce, sizeof(nonce),
                                    aad, sizeof(aad),
                                    (const unsigned char *)plaintext,
                                    ciphertext,
                                    16, tag);
    if (ret != 0) {
        printf("加密失败: -0x%04x\n", -ret);
        return ret;
    }

    printf("\n加密结果:\n");
    print_hex("密文", ciphertext, plaintext_len);
    print_hex("Tag ", tag, 16);

    /* 解密 + 验证认证标签 */
    ret = mbedtls_gcm_auth_decrypt(&gcm, plaintext_len,
                                   nonce, sizeof(nonce),
                                   aad, sizeof(aad),
                                   tag, 16,
                                   ciphertext, decrypted);
    if (ret != 0) {
        printf("解密/认证失败: -0x%04x\n", -ret);
        printf("说明: 如果密文或 AAD 被篡改，认证会失败\n");
        return ret;
    }

    printf("\n解密: \"%.*s\"\n", (int)plaintext_len, decrypted);
    printf("✓ 解密和认证标签验证均通过\n");

    /* 演示篡改检测 */
    printf("\n--- 演示篡改检测 ---\n");
    ciphertext[0] ^= 0x01; /* 篡改密文的第一个字节 */
    ret = mbedtls_gcm_auth_decrypt(&gcm, plaintext_len,
                                   nonce, sizeof(nonce),
                                   aad, sizeof(aad),
                                   tag, 16,
                                   ciphertext, decrypted);
    if (ret != 0) {
        printf("✓ 检测到篡改! 认证失败 (ret = -0x%04x)\n", -ret);
        printf("  GCM 的认证机制成功阻止了数据篡改\n");
    }

    mbedtls_gcm_free(&gcm);
    return 0;
}

/**
 * 示例3：使用通用 Cipher API（推荐方式）
 * 好处：可以在运行时切换算法，代码更通用
 */
static int example_cipher_api(void)
{
    printf("\n=== 示例3: 通用 Cipher API (AES-128-CTR) ===\n");

    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char nonce[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    const char *plaintext = "CTR mode turns block cipher into stream cipher";
    size_t plaintext_len = strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    size_t olen;
    int ret;

    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *cipher_info;

    /* 通过名称获取算法信息 */
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
    printf("算法: %s\n", mbedtls_cipher_info_get_name(cipher_info));
    printf("密钥长度: %d bits\n", (int)mbedtls_cipher_info_get_key_bitlen(cipher_info));
    printf("明文: \"%s\" (%zu bytes)\n", plaintext, plaintext_len);

    /* 加密 */
    mbedtls_cipher_init(&ctx);
    mbedtls_cipher_setup(&ctx, cipher_info);
    mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_ENCRYPT);
    mbedtls_cipher_set_iv(&ctx, nonce, 16);
    mbedtls_cipher_reset(&ctx);

    ret = mbedtls_cipher_update(&ctx, (const unsigned char *)plaintext,
                                plaintext_len, ciphertext, &olen);
    if (ret != 0) {
        printf("加密失败: -0x%04x\n", -ret);
        return ret;
    }

    size_t total_len = olen;
    ret = mbedtls_cipher_finish(&ctx, ciphertext + olen, &olen);
    total_len += olen;
    mbedtls_cipher_free(&ctx);

    print_hex("密文", ciphertext, total_len);

    /* 解密 (CTR 模式加密和解密操作相同) */
    mbedtls_cipher_init(&ctx);
    mbedtls_cipher_setup(&ctx, cipher_info);
    mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_DECRYPT);
    mbedtls_cipher_set_iv(&ctx, nonce, 16);
    mbedtls_cipher_reset(&ctx);

    mbedtls_cipher_update(&ctx, ciphertext, total_len, decrypted, &olen);
    size_t dec_len = olen;
    mbedtls_cipher_finish(&ctx, decrypted + olen, &olen);
    dec_len += olen;
    mbedtls_cipher_free(&ctx);

    decrypted[dec_len] = '\0';
    printf("解密: \"%s\"\n", decrypted);

    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("✓ CTR 模式加密/解密验证通过\n");
        printf("  注意: CTR 模式明文和密文长度相同（无 padding）\n");
    } else {
        printf("✗ 验证失败!\n");
        return -1;
    }

    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 02: 对称加密 (AES)         ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    example_aes_cbc();
    example_aes_gcm();
    example_cipher_api();

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("总结:\n");
    printf("  - AES-CBC: 经典模式，需 padding，无完整性保护\n");
    printf("  - AES-GCM: TLS 首选，AEAD 提供加密+认证\n");
    printf("  - AES-CTR: 流模式，无 padding，无完整性保护\n");
    printf("  - TLS 优先使用 GCM 因为它一步完成加密和完整性校验\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
