/**
 * 示例05：X.509 证书解析与验证
 *
 * 本示例演示：
 * - 自签名 CA 证书创建
 * - 证书链验证
 * - 证书信息提取
 * - 自定义验证回调（参照项目 my_verify）
 *
 * 知识点：
 * 1. X.509 证书结构：
 *    - Version (v3)
 *    - Serial Number
 *    - Signature Algorithm
 *    - Issuer (颁发者)
 *    - Validity (有效期)
 *    - Subject (主体)
 *    - Subject Public Key Info
 *    - Extensions (如 SAN, Key Usage)
 *    - Signature (CA 的签名)
 *
 * 2. 证书链：
 *    Root CA (自签名，预置在信任库)
 *      └── Sub CA (由 Root CA 签名)
 *           └── EE Cert (由 Sub CA 签名) ← 服务器/客户端使用
 *
 * 3. 验证过程：
 *    - 签名验证：逐级验证签名直到信任锚点
 *    - 有效期检查
 *    - 用途检查 (Key Usage)
 *    - 吊销检查 (CRL/OCSP)
 *
 * 在项目 task_mbedtls.c 中的体现：
 * - mbedtls_x509_crt_parse() 加载 CA 和客户端证书
 * - mbedtls_ssl_conf_ca_chain() 设置信任的 CA
 * - mbedtls_ssl_conf_own_cert() 设置客户端证书
 * - my_verify() 自定义验证回调
 * - mbedtls_ssl_get_verify_result() 获取验证结果
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/* 用于演示的自签名 CA 证书 (PEM 格式)
 * 这是一个为教学目的生成的测试证书，运行时动态生成 */

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 20; i++) {
        printf("%02x", data[i]);
    }
    if (len > 20) printf("...");
    printf("\n");
}

/**
 * 辅助：生成自签名 CA 证书
 */
static int generate_self_signed_cert(mbedtls_x509_crt *cert,
                                     mbedtls_pk_context *key,
                                     mbedtls_ctr_drbg_context *ctr_drbg,
                                     const char *subject,
                                     int is_ca)
{
    mbedtls_x509write_cert write_cert;
    mbedtls_mpi serial;
    unsigned char cert_buf[4096];
    int ret;

    /* 初始化证书写入器和序列号 */
    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_init(&serial);

    /* 序列号 = 1（CA 必须为每张证书分配唯一值） */
    mbedtls_mpi_lset(&serial, 1);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    /* 有效期：2024-01-01 ~ 2026-12-31 */
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    /* 颁发者 DN（自签名时 = subject） */
    mbedtls_x509write_crt_set_issuer_name(&write_cert, subject);
    /* 主体 DN（证书持有者身份） */
    mbedtls_x509write_crt_set_subject_name(&write_cert, subject);
    /* 主体公钥（证书中嵌入的公钥） */
    mbedtls_x509write_crt_set_subject_key(&write_cert, key);
    /* 颁发者私钥（用于对证书签名） */
    mbedtls_x509write_crt_set_issuer_key(&write_cert, key);
    /* 签名哈希算法：SHA-256 */
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);

    if (is_ca) {
        /* CA 证书：CA:TRUE, pathlen:-1(无限)，允许签发下级证书 */
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 1, -1);
        /* 用途：签发证书 + 签发 CRL */
        mbedtls_x509write_crt_set_key_usage(&write_cert,
            MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    } else {
        /* EE 证书：CA:FALSE，不能签发其他证书 */
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
        /* 用途：TLS 数字签名 + 密钥加密 */
        mbedtls_x509write_crt_set_key_usage(&write_cert,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    }

    /* 写入 PEM */
    ret = mbedtls_x509write_crt_pem(&write_cert, cert_buf, sizeof(cert_buf),
                                    mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("写证书失败: -0x%04x\n", -ret);
        goto exit;
    }

    /* 解析回 x509_crt 结构 */
    ret = mbedtls_x509_crt_parse(cert, cert_buf, strlen((char *)cert_buf) + 1);
    if (ret != 0) {
        printf("解析证书失败: -0x%04x\n", -ret);
    }

exit:
    mbedtls_x509write_crt_free(&write_cert);
    mbedtls_mpi_free(&serial);
    return ret;
}

/**
 * 辅助：生成由 CA 签名的证书（Sub CA 或 EE）
 * 返回 PEM 格式证书文本（调用者负责 free）
 */
static int generate_signed_cert_pem(unsigned char *buf, size_t buf_size,
                                    mbedtls_pk_context *subject_key,
                                    mbedtls_pk_context *issuer_key,
                                    const char *subject_name,
                                    const char *issuer_name,
                                    mbedtls_ctr_drbg_context *ctr_drbg,
                                    int is_ca)
{
    mbedtls_x509write_cert write_cert;
    mbedtls_mpi serial;
    int ret;

    /* 初始化证书写入器和序列号 */
    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_init(&serial);

    /* 序列号（CA 必须为每张证书分配唯一值） */
    mbedtls_mpi_lset(&serial, is_ca ? 2 : 3);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    /* 有效期 */
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    /* 颁发者 = CA 的 DN */
    mbedtls_x509write_crt_set_issuer_name(&write_cert, issuer_name);
    /* 主体 = EE/Sub CA 的 DN */
    mbedtls_x509write_crt_set_subject_name(&write_cert, subject_name);
    /* 主体公钥 */
    mbedtls_x509write_crt_set_subject_key(&write_cert, subject_key);
    /* 颁发者私钥 = CA 的私钥（签名用） */
    mbedtls_x509write_crt_set_issuer_key(&write_cert, issuer_key);
    /* 签名哈希：SHA-256 */
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);

    if (is_ca) {
        /* Sub CA：CA:TRUE，允许签发下级证书 */
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 1, 0);
        /* 用途：签发证书 + 签发 CRL */
        mbedtls_x509write_crt_set_key_usage(&write_cert,
            MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    } else {
        /* EE：CA:FALSE，不能签发其他证书 */
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
        /* 用途：TLS 数字签名 */
        mbedtls_x509write_crt_set_key_usage(&write_cert,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    }

    ret = mbedtls_x509write_crt_pem(&write_cert, buf, buf_size,
                                    mbedtls_ctr_drbg_random, ctr_drbg);

exit:
    mbedtls_x509write_crt_free(&write_cert);
    mbedtls_mpi_free(&serial);
    return ret;
}

/**
 * 示例1：证书信息提取
 */
static int example_cert_info(mbedtls_x509_crt *cert)
{
    printf("\n=== 示例1: 证书信息提取 ===\n");

    char info_buf[2048];
    int ret;

    ret = mbedtls_x509_crt_info(info_buf, sizeof(info_buf), "  ", cert);
    if (ret < 0) {
        printf("获取证书信息失败\n");
        return ret;
    }
    printf("证书详细信息:\n%s\n", info_buf);

    /* 手动提取关键字段 */
    printf("关键字段提取:\n");
    printf("  版本: v%d\n", cert->version);

    char subject_buf[256], issuer_buf[256];
    mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &cert->subject);
    mbedtls_x509_dn_gets(issuer_buf, sizeof(issuer_buf), &cert->issuer);
    printf("  主体 (Subject): %s\n", subject_buf);
    printf("  颁发者 (Issuer): %s\n", issuer_buf);
    printf("  有效期: %04d-%02d-%02d 至 %04d-%02d-%02d\n",
           cert->valid_from.year, cert->valid_from.mon, cert->valid_from.day,
           cert->valid_to.year, cert->valid_to.mon, cert->valid_to.day);
    printf("  公钥类型: %s\n", mbedtls_pk_get_name(&cert->pk));
    printf("  公钥位数: %zu bits\n", mbedtls_pk_get_bitlen(&cert->pk));
    printf("  是 CA: %s\n", mbedtls_x509_crt_get_ca_istrue(cert) ? "是" : "否");

    return 0;
}

/**
 * 示例2：证书链验证
 * 对应项目中 mbedtls_ssl_get_verify_result() 的逻辑
 */
static int example_cert_chain_verify(mbedtls_x509_crt *ca_cert,
                                     mbedtls_x509_crt *ee_cert)
{
    printf("\n=== 示例2: 证书链验证 ===\n");
    printf("对应项目中 mbedtls_ssl_conf_ca_chain() + 握手验证\n\n");

    uint32_t flags;
    char vrfy_buf[512];
    int ret;

    /* 验证 EE 证书是否由 CA 签名 */
    ret = mbedtls_x509_crt_verify(ee_cert, ca_cert, NULL, NULL, &flags, NULL, NULL);

    if (ret == 0) {
        printf("✓ 证书链验证通过!\n");
        printf("  EE 证书的签名由 CA 证书中的公钥验证成功\n");
    } else {
        printf("证书验证结果: 0x%04x\n", flags);
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s\n", vrfy_buf);
    }

    /* 演示：用错误的 CA 验证 */
    printf("\n--- 演示：使用错误的 CA 验证 ---\n");
    ret = mbedtls_x509_crt_verify(ee_cert, ee_cert, NULL, NULL, &flags, NULL, NULL);
    if (ret != 0) {
        printf("✓ 预期失败! 错误标志: 0x%04x\n", flags);
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s", vrfy_buf);
        printf("  说明: 使用非颁发者的证书验证，签名不匹配\n");
    }

    return 0;
}

/**
 * 示例3：自定义验证回调
 * 参照项目中 my_verify() 的实现
 *
 * 在嵌入式设备中，RTC 可能未设置，需要忽略证书过期错误
 */
static int my_verify_callback(void *data, mbedtls_x509_crt *crt,
                              int depth, uint32_t *flags)
{
    char buf[256];
    int *simulate_no_rtc = (int *)data;

    mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
    printf("  [验证回调] 深度 %d: %s\n", depth, buf);
    printf("  [验证回调] 标志: 0x%04x\n", *flags);

    if (*flags & MBEDTLS_X509_BADCERT_EXPIRED) {
        printf("  [验证回调] 证书已过期!\n");
        if (simulate_no_rtc && *simulate_no_rtc) {
            printf("  [验证回调] RTC 未设置，忽略过期错误 (如项目 my_verify)\n");
            *flags &= ~MBEDTLS_X509_BADCERT_EXPIRED;
        }
    }

    if (*flags & MBEDTLS_X509_BADCERT_FUTURE) {
        printf("  [验证回调] 证书尚未生效!\n");
        if (simulate_no_rtc && *simulate_no_rtc) {
            printf("  [验证回调] RTC 未设置，忽略时间错误\n");
            *flags &= ~MBEDTLS_X509_BADCERT_FUTURE;
        }
    }

    if (*flags == 0) {
        printf("  [验证回调] ✓ 无错误\n");
    }

    return 0; /* 返回 0 继续验证链 */
}

static int example_verify_callback(mbedtls_x509_crt *ca_cert,
                                   mbedtls_x509_crt *ee_cert)
{
    printf("\n=== 示例3: 自定义验证回调 ===\n");
    printf("参照项目 task_mbedtls.c 中 my_verify() 的实现\n\n");

    uint32_t flags;
    int simulate_no_rtc = 1; /* 模拟 RTC 未设置 */

    printf("使用自定义回调验证证书:\n");
    /* 回调会被调用两次：
     *   第 1 次 (depth=0): 验证 EE 证书本身（签名、有效期、Key Usage 等）
     *   第 2 次 (depth=1): 验证 CA 证书（信任锚点，检查自签名是否有效）
     * 即证书链中每张证书都会触发一次回调，从叶子到根依次验证 */
    int ret = mbedtls_x509_crt_verify(ee_cert, ca_cert, NULL, NULL, &flags,
                                      my_verify_callback, &simulate_no_rtc);

    printf("\n项目代码对应:\n");
    printf("  mbedtls_ssl_conf_verify(&conf_ext, my_verify, NULL);\n");
    printf("  // my_verify 中: if(tt==0) *flags &= ~EXPIRED & ~FUTURE\n");

    if (ret == 0 || flags == 0) {
        printf("\n✓ 验证通过（可能忽略了时间相关错误）\n");
    }

    return 0;
}

/**
 * 示例4：三级证书链验证 (Root CA → Sub CA → EE)
 *
 * 对应项目实际场景：
 *   Root CA (自签名，预置在设备信任库)
 *     └── Sub CA (由 Root CA 签名)
 *          └── EE Cert (由 Sub CA 签名，服务器/客户端使用)
 *
 * 验证时 mbedtls_x509_crt_verify 的 ca_chain 参数传入 Sub CA，
 * mbedTLS 自动沿链向上找到 Root CA（信任锚点）。
 * 回调被调用 3 次：depth=0 (EE), depth=1 (Sub CA), depth=2 (Root CA)
 */
static int example_three_level_chain(mbedtls_x509_crt *root_ca,
                                     mbedtls_x509_crt *sub_ca,
                                     mbedtls_x509_crt *ee_cert)
{
    printf("\n=== 示例4: 三级证书链验证 (Root CA → Sub CA → EE) ===\n");
    printf("对应项目: mbedtls_ssl_conf_ca_chain() 加载 Root CA\n");
    printf("          服务器出示 EE 证书 + Sub CA 中间证书\n\n");

    uint32_t flags;
    char vrfy_buf[512];
    int ret;

    /* 验证：ee_cert 已经是链头（next 指向 sub_ca，由 parse 自动建立）
     * mbedTLS 沿链向上验证直到 trust_ca (root_ca) */
    ret = mbedtls_x509_crt_verify(ee_cert, root_ca, NULL, NULL, &flags,
                                  my_verify_callback, NULL);

    if (ret == 0) {
        printf("\n✓ 三级证书链验证通过!\n");
        printf("  验证路径: EE → Sub CA → Root CA (信任锚点)\n");
        printf("  回调调用 3 次: depth=0(EE), depth=1(Sub CA), depth=2(Root CA)\n");
    } else {
        printf("证书验证结果: 0x%04x\n", flags);
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s\n", vrfy_buf);
    }

    /* 演示：信任库中没有 Root CA → 验证失败 */
    printf("\n--- 演示：信任库缺少 Root CA ---\n");
    ret = mbedtls_x509_crt_verify(ee_cert, NULL, NULL, NULL, &flags, NULL, NULL);
    if (ret != 0) {
        printf("✓ 预期失败! 错误标志: 0x%04x\n", flags);
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s", vrfy_buf);
        printf("  说明: 无法到达信任锚点，链不完整\n");
    }

    /* 演示：以 Sub CA 为信任锚点（没有 Root CA 时的降级验证）
     * 此时只验证 EE → Sub CA 两级，回调只调用 2 次：
     *   depth=0 (EE), depth=1 (Sub CA 作为信任锚点)
     * 安全含义：信任 Sub CA = 信任它能签发的所有证书 */
    ee_cert->next = NULL; /* 断开链，避免自动向上验证到 Root CA */
    printf("\n--- 演示：以 Sub CA 为信任锚点（无 Root CA 时的降级验证）---\n");
    ret = mbedtls_x509_crt_verify(ee_cert, sub_ca, NULL, NULL, &flags,
                                  my_verify_callback, NULL);
    if (ret == 0) {
        printf("\n✓ 两级验证通过 (EE → Sub CA)\n");
        printf("  回调只调用 2 次: depth=0(EE), depth=1(Sub CA)\n");
        printf("  说明: trust_ca 可以是链中任何一级 CA，不一定是自签名 Root\n");
    }

    return 0;
}

/**
 * 示例5：CRL 证书吊销检查
 *
 * CRL (Certificate Revocation List) 是 CA 发布的吊销证书列表。
 * 当证书私钥泄露或证书需要提前作废时，CA 将证书序列号加入 CRL。
 *
 * 验证流程中 CRL 的作用：
 *   mbedtls_x509_crt_verify(crt, trust_ca, ca_crl, ...)
 *                                    ^^^^^^^ 第三个参数
 *   对链中每张证书，mbedTLS 会：
 *   1. 找到由该证书颁发者 (issuer) 签发的 CRL
 *   2. 验证 CRL 签名（CRL 必须由对应 CA 签名）
 *   3. 检查 CRL 有效期
 *   4. 在 CRL 中查找该证书的序列号
 *   5. 如果找到 → 设置 MBEDTLS_X509_BADCERT_REVOKED 标志
 *
 * 注意：mbedTLS 只提供 CRL 解析和验证，不提供 CRL 生成。
 * 实际部署中 CRL 由 CA 系统（如 OpenSSL ca 命令）生成。
 *
 * 本示例使用 mbedTLS 测试数据：
 *   - CA: PolarSSL Test CA (test-ca-sha256.crt, serial=03)
 *   - CRL: 吊销了 serial=01 和 serial=03
 *   - 被吊销证书: server1.crt (serial=01)
 *   - 未吊销证书: server2-sha256.crt (serial=02)
 */
static int example_crl_check(void)
{
    printf("\n=== 示例5: CRL 证书吊销检查 ===\n");
    printf("对应项目: mbedtls_x509_crt_verify() 第三个参数 ca_crl\n\n");

    /* mbedTLS 测试数据路径（构建时通过 CMake 传入） */
    const char *ca_file    = MBEDTLS_TEST_DATA_DIR "/test-ca-sha256.crt";
    const char *crl_file   = MBEDTLS_TEST_DATA_DIR "/crl.pem";
    const char *revoked_file  = MBEDTLS_TEST_DATA_DIR "/server1.crt";
    const char *valid_file    = MBEDTLS_TEST_DATA_DIR "/server2-sha256.crt";

    mbedtls_x509_crt ca_cert, revoked_cert, valid_cert;
    mbedtls_x509_crl crl;
    uint32_t flags;
    char vrfy_buf[512];
    int ret;

    mbedtls_x509_crt_init(&ca_cert);
    mbedtls_x509_crt_init(&revoked_cert);
    mbedtls_x509_crt_init(&valid_cert);
    mbedtls_x509_crl_init(&crl);

    /* 1. 加载 CA 证书（CRL 的签名者） */
    ret = mbedtls_x509_crt_parse_file(&ca_cert, ca_file);
    if (ret != 0) {
        printf("加载 CA 证书失败: -0x%04x\n", -ret);
        goto exit;
    }
    printf("CA 证书: %s\n", ca_file);

    /* 2. 加载 CRL（PEM 格式，可包含多个 CRL）
     * mbedtls_x509_crl_parse 支持 PEM 和 DER
     * 多个 CRL 通过 next 链连接（与证书链类似） */
    ret = mbedtls_x509_crl_parse_file(&crl, crl_file);
    if (ret != 0) {
        printf("加载 CRL 失败: -0x%04x\n", -ret);
        goto exit;
    }
    printf("CRL 文件: %s\n", crl_file);

    /* 打印 CRL 信息 */
    char crl_info[512];
    mbedtls_x509_crl_info(crl_info, sizeof(crl_info), "  ", &crl);
    printf("CRL 详情:\n%s\n", crl_info);

    /* 打印吊销条目 */
    printf("  吊销条目:\n");
    const mbedtls_x509_crl_entry *entry = &crl.entry;
    while (entry != NULL && entry->serial.len != 0) {
        printf("    序列号: ");
        for (size_t i = 0; i < entry->serial.len; i++) {
            printf("%02x", entry->serial.p[i]);
        }
        printf("  吊销日期: %04d-%02d-%02d\n",
               entry->revocation_date.year,
               entry->revocation_date.mon,
               entry->revocation_date.day);
        entry = entry->next;
    }

    /* 3. 验证被吊销的证书 (server1, serial=01) */
    printf("\n--- 验证被吊销证书 (server1, serial=01) ---\n");
    ret = mbedtls_x509_crt_parse_file(&revoked_cert, revoked_file);
    if (ret != 0) {
        printf("加载证书失败: -0x%04x\n", -ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_verify(&revoked_cert, &ca_cert, &crl, NULL,
                                  &flags, NULL, NULL);
    if (flags & MBEDTLS_X509_BADCERT_REVOKED) {
        printf("✓ 检测到证书已被吊销!\n");
        printf("  错误标志: 0x%04x\n", flags);
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s", vrfy_buf);
        printf("  说明: server1 的序列号 (01) 在 CRL 中，证书已作废\n");
        printf("  (测试 CRL 使用 SHA-1 签名，额外触发了哈希算法警告)\n");
    } else {
        printf("✗ 未检测到吊销（不应该发生）\n");
    }

    /* 4. 验证未吊销的证书 (server2, serial=02) */
    printf("\n--- 验证未吊销证书 (server2, serial=02) ---\n");
    ret = mbedtls_x509_crt_parse_file(&valid_cert, valid_file);
    if (ret != 0) {
        printf("加载证书失败: -0x%04x\n", -ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_verify(&valid_cert, &ca_cert, &crl, NULL,
                                  &flags, NULL, NULL);
    if (!(flags & MBEDTLS_X509_BADCERT_REVOKED)) {
        printf("✓ 证书未被吊销\n");
        printf("  错误标志: 0x%04x (无 REVOKED 标志)\n", flags);
        printf("  说明: server2 的序列号 (02) 不在 CRL 中\n");
        if (flags != 0) {
            printf("  (测试 CRL 使用 SHA-1 签名，触发了哈希算法警告，与吊销无关)\n");
        }
    } else {
        printf("✗ 证书被吊销（不应该发生）\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s", vrfy_buf);
    }

    /* 5. 演示：不传 CRL 时不会检查吊销 */
    printf("\n--- 演示：不传 CRL（ca_crl=NULL）---\n");
    ret = mbedtls_x509_crt_verify(&revoked_cert, &ca_cert, NULL, NULL,
                                  &flags, NULL, NULL);
    if (!(flags & MBEDTLS_X509_BADCERT_REVOKED)) {
        printf("✓ 验证通过（未检查吊销）\n");
        printf("  错误标志: 0x%04x (无 REVOKED 标志)\n", flags);
        printf("  说明: ca_crl=NULL 时跳过 CRL 检查，被吊销证书也能通过\n");
        printf("  安全含义: 生产环境必须配置 CRL 或 OCSP 才能检测吊销\n");
    }

    /* 6. 手动检查吊销（不经过完整验证流程） */
    printf("\n--- 手动检查: mbedtls_x509_crt_is_revoked() ---\n");
    int is_revoked = mbedtls_x509_crt_is_revoked(&revoked_cert, &crl);
    printf("  server1 (serial=01): %s\n", is_revoked ? "已吊销" : "未吊销");
    is_revoked = mbedtls_x509_crt_is_revoked(&valid_cert, &crl);
    printf("  server2 (serial=02): %s\n", is_revoked ? "已吊销" : "未吊销");

exit:
    mbedtls_x509_crt_free(&ca_cert);
    mbedtls_x509_crt_free(&revoked_cert);
    mbedtls_x509_crt_free(&valid_cert);
    mbedtls_x509_crl_free(&crl);
    return 0;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 05: X.509 证书解析与验证   ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context root_key, sub_key, ee_key;
    mbedtls_x509_crt root_cert, sub_cert, ee_cert;
    int ret;

    const char *pers = "x509_demo";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_pk_init(&root_key);
    mbedtls_pk_init(&sub_key);
    mbedtls_pk_init(&ee_key);
    mbedtls_x509_crt_init(&root_cert);
    mbedtls_x509_crt_init(&sub_cert);
    mbedtls_x509_crt_init(&ee_cert);

    /* 生成 Root CA 密钥对 (RSA-2048) */
    printf("\n生成 Root CA 密钥对 (RSA-2048)...\n");
    mbedtls_pk_setup(&root_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(root_key), mbedtls_ctr_drbg_random,
                              &ctr_drbg, 2048, 65537);
    if (ret != 0) { printf("Root CA 密钥生成失败\n"); goto exit; }

    /* 生成 Sub CA 密钥对 (RSA-2048) */
    printf("生成 Sub CA 密钥对 (RSA-2048)...\n");
    mbedtls_pk_setup(&sub_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(sub_key), mbedtls_ctr_drbg_random,
                              &ctr_drbg, 2048, 65537);
    if (ret != 0) { printf("Sub CA 密钥生成失败\n"); goto exit; }

    /* 生成 EE 密钥对 (ECC P-256) */
    printf("生成 EE 密钥对 (ECC P-256)...\n");
    mbedtls_pk_setup(&ee_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(ee_key),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { printf("EE 密钥生成失败\n"); goto exit; }

    /* 生成自签名 Root CA 证书 */
    printf("生成自签名 Root CA 证书...\n");
    ret = generate_self_signed_cert(&root_cert, &root_key, &ctr_drbg,
                                    "CN=Demo Root CA,O=mbedTLS Tutorial,C=CN", 1);
    if (ret != 0) goto exit;

    /* 生成 Root CA 签名的 Sub CA 证书 (PEM) */
    printf("生成 Sub CA 证书（由 Root CA 签名）...\n");
    unsigned char sub_pem[4096];
    ret = generate_signed_cert_pem(sub_pem, sizeof(sub_pem), &sub_key, &root_key,
                                   "CN=Demo Sub CA,O=mbedTLS Tutorial,C=CN",
                                   "CN=Demo Root CA,O=mbedTLS Tutorial,C=CN",
                                   &ctr_drbg, 1);
    if (ret != 0) goto exit;

    /* 生成 Sub CA 签名的 EE 证书 (PEM) */
    printf("生成 EE 证书（由 Sub CA 签名）...\n");
    unsigned char ee_pem[4096];
    ret = generate_signed_cert_pem(ee_pem, sizeof(ee_pem), &ee_key, &sub_key,
                                   "CN=demo-server.local,O=mbedTLS Tutorial,C=CN",
                                   "CN=Demo Sub CA,O=mbedTLS Tutorial,C=CN",
                                   &ctr_drbg, 0);
    if (ret != 0) goto exit;

    /* 多次 parse 到同一个结构体，mbedTLS 自动追加到链尾（建立 next 链）
     * 这是官方推荐方式，不需要手动拼接 PEM 或修改 next
     *
     * 注意：链顺序 = parse 顺序 = 验证顺序，必须从叶子到根：
     *   EE → Sub CA → (Root CA 在 trust_ca 中，不放在链里)
     * 如果顺序反了（Sub CA → EE），验证会失败，
     * 因为 mbedTLS 严格沿 next 链逐级向上匹配 issuer。
     * TLS 中服务器发送证书链也遵循此顺序 (RFC 5246)。 */
    ret = mbedtls_x509_crt_parse(&ee_cert, ee_pem, sizeof(ee_pem));
    if (ret != 0) { printf("解析 EE 证书失败: -0x%04x\n", -ret); goto exit; }
    ret = mbedtls_x509_crt_parse(&ee_cert, sub_pem, sizeof(sub_pem));
    if (ret != 0) { printf("解析 Sub CA 证书失败: -0x%04x\n", -ret); goto exit; }
    /* 现在: ee_cert (链头) → ee_cert->next (Sub CA) → NULL */
    sub_cert = *ee_cert.next;

    /* 运行示例 */
    example_cert_info(&root_cert);
    example_cert_chain_verify(&root_cert, &sub_cert);
    example_verify_callback(&root_cert, &sub_cert);
    example_three_level_chain(&root_cert, &sub_cert, &ee_cert);
    example_crl_check();

exit:
    /* ee_cert 是链头，free 会自动释放整条链（包括 sub_cert） */
    mbedtls_x509_crt_free(&ee_cert);
    mbedtls_x509_crt_free(&root_cert);
    mbedtls_pk_free(&ee_key);
    mbedtls_pk_free(&sub_key);
    mbedtls_pk_free(&root_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("总结:\n");
    printf("  - mbedtls_x509_crt_parse(): 从 PEM/DER 加载证书\n");
    printf("  - mbedtls_x509_crt_verify(): 验证证书链 (含 CRL 吊销检查)\n");
    printf("  - mbedtls_x509_crl_parse(): 加载 CRL 吊销列表\n");
    printf("  - mbedtls_x509_crt_is_revoked(): 手动检查证书是否被吊销\n");
    printf("  - 验证回调: 可自定义忽略/处理特定错误\n");
    printf("  - 项目模式: CA → SubCA → EE 三级证书链\n");
    printf("  - mbedtls_ssl_conf_ca_chain(): 配置信任锚点\n");
    printf("  - mbedtls_ssl_conf_own_cert(): 配置客户端证书\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
