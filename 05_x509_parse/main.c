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
#include "mbedtls/x509_csr.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/oid.h"

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

    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_init(&serial);

    /* 设置证书属性 */
    mbedtls_mpi_lset(&serial, 1);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    mbedtls_x509write_crt_set_issuer_name(&write_cert, subject);
    mbedtls_x509write_crt_set_subject_name(&write_cert, subject);
    mbedtls_x509write_crt_set_subject_key(&write_cert, key);
    mbedtls_x509write_crt_set_issuer_key(&write_cert, key);
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);

    if (is_ca) {
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 1, -1);
        mbedtls_x509write_crt_set_key_usage(&write_cert,
            MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    } else {
        mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
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
 * 辅助：生成由 CA 签名的 EE 证书
 */
static int generate_signed_cert(mbedtls_x509_crt *cert,
                                mbedtls_pk_context *subject_key,
                                mbedtls_pk_context *issuer_key,
                                const char *subject_name,
                                const char *issuer_name,
                                mbedtls_ctr_drbg_context *ctr_drbg)
{
    mbedtls_x509write_cert write_cert;
    mbedtls_mpi serial;
    unsigned char cert_buf[4096];
    int ret;

    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_init(&serial);

    mbedtls_mpi_lset(&serial, 2);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    mbedtls_x509write_crt_set_issuer_name(&write_cert, issuer_name);
    mbedtls_x509write_crt_set_subject_name(&write_cert, subject_name);
    mbedtls_x509write_crt_set_subject_key(&write_cert, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&write_cert, issuer_key);
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
    mbedtls_x509write_crt_set_key_usage(&write_cert,
        MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

    ret = mbedtls_x509write_crt_pem(&write_cert, cert_buf, sizeof(cert_buf),
                                    mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) goto exit;

    ret = mbedtls_x509_crt_parse(cert, cert_buf, strlen((char *)cert_buf) + 1);

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

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 05: X.509 证书解析与验证   ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context ca_key, ee_key;
    mbedtls_x509_crt ca_cert, ee_cert;
    int ret;

    const char *pers = "x509_demo";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&ee_key);
    mbedtls_x509_crt_init(&ca_cert);
    mbedtls_x509_crt_init(&ee_cert);

    /* 生成 CA 密钥对 */
    printf("\n生成 CA 密钥对 (RSA-2048)...\n");
    mbedtls_pk_setup(&ca_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ca_key), mbedtls_ctr_drbg_random,
                              &ctr_drbg, 2048, 65537);
    if (ret != 0) { printf("CA 密钥生成失败\n"); goto exit; }

    /* 生成 EE 密钥对 */
    printf("生成 EE 密钥对 (ECC P-256)...\n");
    mbedtls_pk_setup(&ee_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(ee_key),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { printf("EE 密钥生成失败\n"); goto exit; }

    /* 生成自签名 CA 证书 */
    printf("生成自签名 CA 证书...\n");
    ret = generate_self_signed_cert(&ca_cert, &ca_key, &ctr_drbg,
                                    "CN=Demo Root CA,O=mbedTLS Tutorial,C=CN", 1);
    if (ret != 0) goto exit;

    /* 生成 CA 签名的 EE 证书 */
    printf("生成 EE 证书（由 CA 签名）...\n");
    ret = generate_signed_cert(&ee_cert, &ee_key, &ca_key,
                               "CN=demo-server.local,O=mbedTLS Tutorial,C=CN",
                               "CN=Demo Root CA,O=mbedTLS Tutorial,C=CN",
                               &ctr_drbg);
    if (ret != 0) goto exit;

    /* 运行示例 */
    example_cert_info(&ca_cert);
    example_cert_chain_verify(&ca_cert, &ee_cert);
    example_verify_callback(&ca_cert, &ee_cert);

exit:
    mbedtls_x509_crt_free(&ee_cert);
    mbedtls_x509_crt_free(&ca_cert);
    mbedtls_pk_free(&ee_key);
    mbedtls_pk_free(&ca_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("总结:\n");
    printf("  - mbedtls_x509_crt_parse(): 从 PEM/DER 加载证书\n");
    printf("  - mbedtls_x509_crt_verify(): 验证证书链\n");
    printf("  - 验证回调: 可自定义忽略/处理特定错误\n");
    printf("  - 项目模式: CA → SubCA → EE 三级证书链\n");
    printf("  - mbedtls_ssl_conf_ca_chain(): 配置信任锚点\n");
    printf("  - mbedtls_ssl_conf_own_cert(): 配置客户端证书\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 所有示例运行完成\n");
    return 0;
}
