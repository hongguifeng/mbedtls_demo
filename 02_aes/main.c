/**
 * 示例02：对称加密 (AES) —— 三种模式的对比实验
 *
 * 本示例用**同一份明文、同一把密钥**分别走 CBC / GCM / CTR 三种模式，
 * 通过对比实验直观展示它们在功能和使用上的区别：
 *
 *   实验1  基本加解密      —— 三种模式都能加密解密，但 API 形态不同
 *   实验2  密文长度对比    —— 揭示 padding 差异（CBC 膨胀，GCM/CTR 不膨胀）
 *   实验3  篡改检测对比    —— 揭示完整性差异（只有 GCM 能发现篡改）
 *   实验4  通用 Cipher API —— 运行时切换算法的推荐写法
 *
 * 知识点：
 * 1. 对称加密使用同一密钥进行加密和解密，AES 密钥长度 128/192/256 bit
 * 2. 加密模式决定了安全特性：
 *    - CBC: 需要 IV + padding，密文是 16 字节整数倍，不提供认证
 *    - GCM: 需要 Nonce，密文与明文等长，额外产生 16 字节 Auth Tag（AEAD）
 *    - CTR: 需要 Nonce，密文与明文等长，将块密码转为流密码，不提供认证
 * 3. TLS 1.2/1.3 使用 AES-GCM 作为数据加密，因为一步完成加密+完整性校验
 *
 * 在 TLS 中的位置：
 * - 握手完成后双方协商出对称密钥
 * - 所有应用数据用该密钥通过 AES-GCM 加密
 * - 每条记录使用不同的 IV（隐式序号 + 固定部分）
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/cipher.h"

/* ────────────────────────────────────────────────────────────
 * 公共测试数据：三种模式共用，保证对比公平
 * ──────────────────────────────────────────────────────────── */

/* 256-bit 密钥（三种模式统一使用，便于对比） */
static const unsigned char g_key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

/* 明文：故意选 20 字节（不是 16 的整数倍），用来暴露 CBC 的 padding 行为 */
static const char *g_plaintext = "AES mode compare!";
static const size_t g_pt_len = 19; /* strlen，不含 '\0' */

/* 各模式的 IV/Nonce（长度不同本身就是区别之一） */
static const unsigned char g_iv_cbc[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char g_nonce_gcm[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};
static const unsigned char g_nonce_ctr[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/* GCM 的 AAD：关联数据（类似 TLS 记录头，不加密但需要认证） */
static const unsigned char g_aad[] = {0x17, 0x03, 0x03, 0x00, 0x13};

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%2zu B): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* ────────────────────────────────────────────────────────────
 * 实验1：基本加解密 —— 三种模式的 API 形态对比
 *
 * 观察重点：
 *   - CBC 用 mbedtls_aes_crypt_cbc()，一次调用完成整块加解密
 *   - GCM 用 mbedtls_gcm_crypt_and_tag()，加密时同时产出 Auth Tag
 *   - CTR 用通用 cipher API，update/finish 两步（流式接口）
 * ──────────────────────────────────────────────────────────── */
static int experiment_basic(void)
{
    printf("\n════════ 实验1: 基本加解密（同一明文 + 同一密钥）════════\n");
    printf("明文: \"%s\" (%zu bytes)\n", g_plaintext, g_pt_len);

    unsigned char ct[64], pt[64];

    /* ── CBC ── */
    printf("\n[CBC] 底层 aes API，一次调用完成：\n");
    {
        mbedtls_aes_context aes;
        unsigned char iv[16];
        memcpy(iv, g_iv_cbc, 16);
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, g_key, 256);
        /* 注意：CBC 要求长度是 16 的整数倍，这里用 32 字节明文演示 */
        const char *cbc_pt = "AES-CBC needs 16-byte align!"; /* 28 字节 -> 需 padding */
        /* 为简化，这里用刚好 32 字节的明文 */
        const char *cbc_pt2 = "0123456789abcdef0123456789abcdef"; /* 32 字节 */
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv,
                              (const unsigned char *)cbc_pt2, ct);
        mbedtls_aes_free(&aes);
        print_hex("  密文", ct, 32);

        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, g_key, 256);
        memcpy(iv, g_iv_cbc, 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv, ct, pt);
        mbedtls_aes_free(&aes);
        printf("  解密: \"%.*s\"\n", 32, pt);
        (void)cbc_pt;
    }

    /* ── GCM ── */
    printf("\n[GCM] 底层 gcm API，加密时同时产出 Auth Tag：\n");
    {
        mbedtls_gcm_context gcm;
        unsigned char tag[16];
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, g_key, 256);
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, g_pt_len,
                                  g_nonce_gcm, 12,
                                  g_aad, sizeof(g_aad),
                                  (const unsigned char *)g_plaintext, ct,
                                  16, tag);
        print_hex("  密文", ct, g_pt_len);
        print_hex("  Tag ", tag, 16);

        mbedtls_gcm_auth_decrypt(&gcm, g_pt_len,
                                 g_nonce_gcm, 12,
                                 g_aad, sizeof(g_aad),
                                 tag, 16, ct, pt);
        mbedtls_gcm_free(&gcm);
        printf("  解密: \"%.*s\"\n", (int)g_pt_len, pt);
    }

    /* ── CTR ── */
    printf("\n[CTR] 通用 cipher API，update + finish 两步（流式）：\n");
    {
        mbedtls_cipher_context_t ctx;
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
        size_t olen;

        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_ENCRYPT);
        mbedtls_cipher_set_iv(&ctx, g_nonce_ctr, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, (const unsigned char *)g_plaintext,
                              g_pt_len, ct, &olen);
        size_t total = olen;
        mbedtls_cipher_finish(&ctx, ct + olen, &olen);
        total += olen;
        mbedtls_cipher_free(&ctx);
        print_hex("  密文", ct, total);

        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_DECRYPT);
        mbedtls_cipher_set_iv(&ctx, g_nonce_ctr, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, ct, total, pt, &olen);
        size_t dlen = olen;
        mbedtls_cipher_finish(&ctx, pt + olen, &olen);
        dlen += olen;
        mbedtls_cipher_free(&ctx);
        printf("  解密: \"%.*s\"\n", (int)dlen, pt);
    }

    printf("\n→ 三种模式都能正确加解密，但 API 形态各不相同：\n");
    printf("  CBC: 一次调用，要求 16 字节对齐\n");
    printf("  GCM: 一次调用，额外产出 16 字节 Tag\n");
    printf("  CTR: update/finish 两步，流式接口\n");
    return 0;
}

/* ────────────────────────────────────────────────────────────
 * 实验2：密文长度对比 —— 揭示 padding 差异
 *
 * 用同一份 19 字节明文，观察各模式输出的密文长度：
 *   - CBC: 19 -> 32 字节（padding 到 16 的整数倍，膨胀 68%）
 *   - GCM: 19 -> 19 字节（等长，另加 16 字节 Tag）
 *   - CTR: 19 -> 19 字节（等长，无额外开销）
 *
 * 这就是为什么 TLS 选 GCM/CTR 而不是 CBC：
 *   带宽敏感场景下 CBC 的 padding 开销不可接受
 * ──────────────────────────────────────────────────────────── */
static int experiment_length(void)
{
    printf("\n════════ 实验2: 密文长度对比（明文 = %zu 字节）════════\n", g_pt_len);

    unsigned char ct[64];
    size_t cbc_len = 0, gcm_len = 0, ctr_len = 0;

    /* CBC：19 字节 -> 需要 padding 到 32 字节 */
    {
        mbedtls_aes_context aes;
        unsigned char iv[16];
        /* CBC 要求输入是 16 的整数倍，手动 pad 到 32 字节 */
        unsigned char padded[32];
        memset(padded, 0, sizeof(padded));
        memcpy(padded, g_plaintext, g_pt_len);
        memcpy(iv, g_iv_cbc, 16);
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, g_key, 256);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv, padded, ct);
        mbedtls_aes_free(&aes);
        cbc_len = 32;
    }

    /* GCM：19 字节 -> 19 字节密文 + 16 字节 Tag */
    {
        mbedtls_gcm_context gcm;
        unsigned char tag[16];
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, g_key, 256);
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, g_pt_len,
                                  g_nonce_gcm, 12,
                                  g_aad, sizeof(g_aad),
                                  (const unsigned char *)g_plaintext, ct,
                                  16, tag);
        mbedtls_gcm_free(&gcm);
        gcm_len = g_pt_len; /* 密文等长，Tag 另算 */
    }

    /* CTR：19 字节 -> 19 字节 */
    {
        mbedtls_cipher_context_t ctx;
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
        size_t olen;
        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_ENCRYPT);
        mbedtls_cipher_set_iv(&ctx, g_nonce_ctr, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, (const unsigned char *)g_plaintext,
                              g_pt_len, ct, &olen);
        size_t total = olen;
        mbedtls_cipher_finish(&ctx, ct + olen, &olen);
        total += olen;
        mbedtls_cipher_free(&ctx);
        ctr_len = total;
    }

    printf("\n  模式    明文长度   密文长度   额外开销        说明\n");
    printf("  ─────────────────────────────────────────────────────\n");
    printf("  CBC      %2zu B       %2zu B       +%2zu B         padding 到 16 字节对齐\n",
           g_pt_len, cbc_len, cbc_len - g_pt_len);
    printf("  GCM      %2zu B       %2zu B       +16 B Tag       密文等长，Tag 单独传输\n",
           g_pt_len, gcm_len);
    printf("  CTR      %2zu B       %2zu B       +0 B            密文等长，无额外开销\n",
           g_pt_len, ctr_len);

    printf("\n→ CBC 的 padding 使密文膨胀 %zu%%，GCM/CTR 无膨胀\n",
           (cbc_len - g_pt_len) * 100 / g_pt_len);
    printf("→ TLS 选 GCM：等长 + 自带认证，带宽和安全性兼得\n");
    return 0;
}

/* ────────────────────────────────────────────────────────────
 * 实验3：篡改检测对比 —— 揭示完整性差异
 *
 * 对密文的第一个字节做 XOR 篡改，观察各模式的反应：
 *   - CBC: 解密"成功"，但输出是乱码（静默损坏，无法检测）
 *   - GCM: 认证失败，明确报错（AEAD 的核心价值）
 *   - CTR: 解密"成功"，但输出是乱码（静默损坏，无法检测）
 *
 * 这就是 AEAD（认证加密）的意义：
 *   不仅加密，还能验证数据在传输中未被篡改
 * ──────────────────────────────────────────────────────────── */
static int experiment_tamper(void)
{
    printf("\n════════ 实验3: 篡改检测（密文首字节 XOR 0x01）════════\n");

    unsigned char ct[64], pt[64];

    /* ── CBC：篡改后解密"成功"但输出乱码 ── */
    printf("\n[CBC] 篡改后解密：\n");
    {
        mbedtls_aes_context aes;
        unsigned char iv[16];
        const char *cbc_pt = "0123456789abcdef0123456789abcdef";
        memcpy(iv, g_iv_cbc, 16);
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, g_key, 256);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv,
                              (const unsigned char *)cbc_pt, ct);
        mbedtls_aes_free(&aes);

        ct[0] ^= 0x01; /* 篡改！ */

        memcpy(iv, g_iv_cbc, 16);
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, g_key, 256);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv, ct, pt);
        mbedtls_aes_free(&aes);

        printf("  解密结果: ");
        for (int i = 0; i < 32; i++) {
            if (pt[i] >= 32 && pt[i] < 127) printf("%c", pt[i]);
            else printf(".");
        }
        printf("\n");
        printf("  → 解密没有报错，但输出是乱码（静默损坏，无法检测）\n");
    }

    /* ── GCM：篡改后认证失败 ── */
    printf("\n[GCM] 篡改后解密：\n");
    {
        mbedtls_gcm_context gcm;
        unsigned char tag[16];
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, g_key, 256);
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, g_pt_len,
                                  g_nonce_gcm, 12,
                                  g_aad, sizeof(g_aad),
                                  (const unsigned char *)g_plaintext, ct,
                                  16, tag);

        ct[0] ^= 0x01; /* 篡改！ */

        int ret = mbedtls_gcm_auth_decrypt(&gcm, g_pt_len,
                                           g_nonce_gcm, 12,
                                           g_aad, sizeof(g_aad),
                                           tag, 16, ct, pt);
        mbedtls_gcm_free(&gcm);

        if (ret != 0) {
            printf("  → 认证失败 (ret = -0x%04x)，篡改被成功检测！\n", -ret);
            printf("  → GCM 的 Auth Tag 保证了数据完整性\n");
        }
    }

    /* ── CTR：篡改后解密"成功"但输出乱码 ── */
    printf("\n[CTR] 篡改后解密：\n");
    {
        mbedtls_cipher_context_t ctx;
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
        size_t olen;

        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_ENCRYPT);
        mbedtls_cipher_set_iv(&ctx, g_nonce_ctr, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, (const unsigned char *)g_plaintext,
                              g_pt_len, ct, &olen);
        size_t total = olen;
        mbedtls_cipher_finish(&ctx, ct + olen, &olen);
        total += olen;
        mbedtls_cipher_free(&ctx);

        ct[0] ^= 0x01; /* 篡改！ */

        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_DECRYPT);
        mbedtls_cipher_set_iv(&ctx, g_nonce_ctr, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, ct, total, pt, &olen);
        size_t dlen = olen;
        mbedtls_cipher_finish(&ctx, pt + olen, &olen);
        dlen += olen;
        mbedtls_cipher_free(&ctx);

        printf("  解密结果: ");
        for (size_t i = 0; i < dlen; i++) {
            if (pt[i] >= 32 && pt[i] < 127) printf("%c", pt[i]);
            else printf(".");
        }
        printf("\n");
        printf("  → 解密没有报错，但输出是乱码（静默损坏，无法检测）\n");
    }

    printf("\n→ 只有 GCM 能检测篡改，CBC/CTR 的损坏是静默的\n");
    printf("→ 这就是 TLS 必须用 AEAD 模式（GCM/CCM）的根本原因\n");
    return 0;
}

/* ────────────────────────────────────────────────────────────
 * 实验4：通用 Cipher API —— 运行时切换算法
 *
 * 实际项目中通常不直接调 mbedtls_aes_crypt_cbc() 或
 * mbedtls_gcm_crypt_and_tag()，而是用通用 cipher API：
 *   - 通过 mbedtls_cipher_info_from_type() 在运行时选择算法
 *   - 同一套 init/setup/setkey/free 流程
 *   - 切换算法只需改一个 type 参数，不用改代码逻辑
 *
 * 这里演示用通用 API 分别跑 CBC 和 GCM：
 *   - CBC: 用 update/finish 流式接口
 *   - GCM: 用 auth_encrypt_ext/auth_decrypt_ext AEAD 接口（mbedTLS 3.x 新增）
 * ──────────────────────────────────────────────────────────── */
static int experiment_cipher_api(void)
{
    printf("\n════════ 实验4: 通用 Cipher API（运行时切换算法）════════\n");

    const char *pt = "Generic cipher API demo";
    size_t pt_len = strlen(pt);
    unsigned char ct[64], out[64];
    size_t olen;

    /* 用通用 API 跑 CBC */
    printf("\n[通用 API → CBC]\n");
    {
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        printf("  算法: %s, 密钥: %d bits, IV: %d bytes\n",
               mbedtls_cipher_info_get_name(info),
               (int)mbedtls_cipher_info_get_key_bitlen(info),
               (int)mbedtls_cipher_info_get_iv_size(info));

        mbedtls_cipher_context_t ctx;
        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_ENCRYPT);
        mbedtls_cipher_set_iv(&ctx, g_iv_cbc, 16);
        mbedtls_cipher_reset(&ctx);
        mbedtls_cipher_update(&ctx, (const unsigned char *)pt, pt_len, ct, &olen);
        size_t total = olen;
        mbedtls_cipher_finish(&ctx, ct + olen, &olen);
        total += olen;
        mbedtls_cipher_free(&ctx);
        printf("  密文长度: %zu bytes (含 padding)\n", total);
    }

    /* 用通用 API 跑 GCM（AEAD 接口） */
    printf("\n[通用 API → GCM (AEAD)]\n");
    {
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
        printf("  算法: %s, 密钥: %d bits, IV: %d bytes\n",
               mbedtls_cipher_info_get_name(info),
               (int)mbedtls_cipher_info_get_key_bitlen(info),
               (int)mbedtls_cipher_info_get_iv_size(info));

        mbedtls_cipher_context_t ctx;
        mbedtls_cipher_init(&ctx);
        mbedtls_cipher_setup(&ctx, info);
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_ENCRYPT);

        /* AEAD 加密：iv + aad + 明文 → 密文 + tag */
        int ret = mbedtls_cipher_auth_encrypt_ext(
            &ctx,
            g_nonce_gcm, 12,           /* nonce */
            g_aad, sizeof(g_aad),      /* 关联数据 */
            (const unsigned char *)pt, pt_len,  /* 明文 */
            ct, sizeof(ct),            /* 输出缓冲区 */
            &olen, 16);                /* tag 长度 */
        if (ret != 0) {
            printf("  加密失败: -0x%04x\n", -ret);
            mbedtls_cipher_free(&ctx);
            return ret;
        }
        printf("  密文+Tag 长度: %zu bytes (密文 %zu + Tag 16)\n",
               olen, olen - 16);

        /* AEAD 解密：验证 tag + 解密 */
        mbedtls_cipher_setkey(&ctx, g_key, 256, MBEDTLS_DECRYPT);
        ret = mbedtls_cipher_auth_decrypt_ext(
            &ctx,
            g_nonce_gcm, 12,
            g_aad, sizeof(g_aad),
            ct, olen,                  /* 密文+tag */
            out, sizeof(out),
            &olen, 16);
        mbedtls_cipher_free(&ctx);
        if (ret != 0) {
            printf("  解密失败: -0x%04x\n", -ret);
            return ret;
        }
        printf("  解密: \"%.*s\"\n", (int)olen, out);
    }

    printf("\n→ 通用 API 的优势：切换算法只改 type 参数，代码结构不变\n");
    printf("→ CBC 用 update/finish，GCM 用 auth_encrypt_ext/auth_decrypt_ext\n");
    printf("→ 同一套 init/setup/setkey/free 生命周期，接口按模式选择\n");
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 02: 对称加密 (AES) 模式对比实验     ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    experiment_basic();
    experiment_length();
    experiment_tamper();
    experiment_cipher_api();

    printf("\n══════════════════════════════════════════════════════\n");
    printf("  模式    padding   密文长度   完整性   TLS 适用性\n");
    printf("  ─────────────────────────────────────────────────────\n");
    printf("  CBC     需要      膨胀       无       不推荐\n");
    printf("  GCM     不需要    等长+Tag   有(AEAD)  首选 ✓\n");
    printf("  CTR     不需要    等长       无       可用但需额外 MAC\n");
    printf("══════════════════════════════════════════════════════\n");

    printf("\n✓ 所有实验运行完成\n");
    return 0;
}
