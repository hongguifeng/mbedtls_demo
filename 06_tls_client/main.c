/**
 * 示例06：TLS 客户端基础连接
 *
 * 本示例演示完整的 TLS 单向认证连接流程：
 * 1. 初始化 mbedTLS 组件
 * 2. 加载 CA 证书（系统证书或自定义 CA）
 * 3. 配置 SSL 上下文
 * 4. 建立 TCP 连接
 * 5. 执行 TLS 握手
 * 6. 发送 HTTPS 请求
 * 7. 接收响应
 * 8. 关闭连接
 *
 * 知识点：
 * 1. SSL Context: 管理单个连接的状态
 * 2. SSL Config: 可被多个连接共享的配置
 * 3. 证书验证模式:
 *    - MBEDTLS_SSL_VERIFY_NONE: 不验证（不安全!）
 *    - MBEDTLS_SSL_VERIFY_OPTIONAL: 验证但不强制
 *    - MBEDTLS_SSL_VERIFY_REQUIRED: 必须验证（推荐）
 * 4. SNI (Server Name Indication): 虚拟主机支持
 *
 * 在项目 task_mbedtls.c 中的对应：
 * - mbedtls_ssl_config_defaults(): 配置默认值
 * - mbedtls_ssl_conf_authmode(): 设置验证模式 (VERIFY_REQUIRED)
 * - mbedtls_ssl_conf_ca_chain(): 加载 CA 证书
 * - mbedtls_ssl_set_hostname(): 设置 SNI
 * - mbedtls_ssl_handshake(): 执行握手
 *
 * 连接目标: httpbin.org (HTTPS)
 * 注意: 需要网络访问
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

/* 调试回调 - 参照项目中 my_debug() 的实现 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    (void)ctx;
    const char *lvl_str;
    switch (level) {
        case 0: lvl_str = "FATAL"; break;
        case 1: lvl_str = "ERROR"; break;
        case 2: lvl_str = "STATE"; break;
        case 3: lvl_str = "INFO "; break;
        case 4: lvl_str = "VERB "; break;
        default: lvl_str = "?????"; break;
    }
    /* 只打印 level <= 2 的信息，避免过于冗长 */
    if (level <= 2) {
        printf("TLS|%s| %s:%04d: %s", lvl_str, file, line, str);
    }
}

/**
 * 验证回调 - 参照项目中 my_verify() 的实现
 */
static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    char buf[256];
    (void)data;

    mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
    printf("  [验证] 深度 %d: %s\n", depth, buf);

    if (*flags) {
        char flag_buf[256];
        mbedtls_x509_crt_verify_info(flag_buf, sizeof(flag_buf), "    ! ", *flags);
        printf("%s", flag_buf);
    } else {
        printf("    ✓ 无错误\n");
    }

    return 0; /* 返回 0 继续 */
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 06: TLS 客户端基础连接     ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    int ret;
    char err_buf[128];

    const char *server_name = "httpbin.org";
    const char *server_port = "443";

    /* HTTP GET 请求 */
    const char *request =
        "GET /get HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Connection: close\r\n"
        "\r\n";

    unsigned char response[4096];

    /*
     * 步骤0: 初始化所有 mbedTLS 组件
     * 对应项目: mbedtls_ssl_init(), mbedtls_net_init() 等
     */
    printf("\n[步骤0] 初始化 mbedTLS 组件...\n");
    psa_crypto_init();
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    /*
     * 步骤1: 初始化随机数生成器
     * 对应项目: psa_crypto_init() (项目使用 PSA API)
     * RNG 是 TLS 安全的基础：
     * - 生成 ClientHello 随机数
     * - ECDHE 临时密钥
     * - GCM nonce
     */
    printf("[步骤1] 初始化随机数生成器...\n");
    const char *pers = "tls_client_demo";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("  失败: %s\n", err_buf);
        goto exit;
    }
    printf("  ✓ CTR-DRBG 初始化成功\n");

    /*
     * 步骤2: 加载 CA 证书
     * 对应项目: mbedtls_x509_crt_parse(&cacert_ext, ing_cert_get_address(...), ...)
     *
     * Linux 系统 CA 证书通常在：
     * - /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu)
     * - /etc/pki/tls/certs/ca-bundle.crt (RHEL/CentOS)
     */
    printf("[步骤2] 加载 CA 证书...\n");
    /* 尝试常见的系统 CA 证书路径 */
    ret = mbedtls_x509_crt_parse_file(&cacert, "/etc/ssl/certs/ca-certificates.crt");
    if (ret != 0) {
        ret = mbedtls_x509_crt_parse_file(&cacert, "/etc/pki/tls/certs/ca-bundle.crt");
    }
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("  ⚠ 加载系统 CA 失败: %s\n", err_buf);
        printf("  将使用 VERIFY_NONE 模式（仅演示，生产环境不推荐!）\n");
    } else {
        printf("  ✓ 已加载 CA 证书\n");
    }

    /*
     * 步骤3: 配置 SSL
     * 对应项目: mbedtls_ssl_config_defaults(), mbedtls_ssl_conf_*() 系列调用
     */
    printf("[步骤3] 配置 SSL/TLS...\n");
    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,       /* 客户端模式 */
                                      MBEDTLS_SSL_TRANSPORT_STREAM, /* TCP 流 */
                                      MBEDTLS_SSL_PRESET_DEFAULT);  /* 默认安全配置 */
    if (ret != 0) {
        printf("  配置默认值失败\n");
        goto exit;
    }

    /* 设置 TLS 版本范围 - 对应项目:
     * mbedtls_ssl_conf_min_tls_version(&conf_ext, MBEDTLS_SSL_VERSION_TLS1_2);
     * mbedtls_ssl_conf_max_tls_version(&conf_ext, MBEDTLS_SSL_VERSION_TLS1_3); */
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_3);
    printf("  TLS 版本: 1.2 ~ 1.3\n");

    /* 证书验证模式 - 对应项目:
     * mbedtls_ssl_conf_authmode(&conf_ext, MBEDTLS_SSL_VERIFY_REQUIRED); */
    if (cacert.version != 0) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        printf("  认证模式: VERIFY_REQUIRED (强制验证服务器证书)\n");
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        printf("  认证模式: VERIFY_NONE (⚠ 不验证! 仅演示)\n");
    }

    /* RNG 和调试 */
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
    mbedtls_debug_set_threshold(2); /* 0=不打印, 1=Error, 2=State, 3=Info, 4=Verbose */

    /* 验证回调 - 对应项目:
     * mbedtls_ssl_conf_verify(&conf_ext, my_verify, NULL); */
    mbedtls_ssl_conf_verify(&conf, my_verify, NULL);

    /* 应用配置到 SSL 上下文 */
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        printf("  ssl_setup 失败\n");
        goto exit;
    }

    /* 设置 SNI - 对应项目:
     * mbedtls_ssl_set_hostname(&ssl, "CSC-Server-WCRT"); */
    ret = mbedtls_ssl_set_hostname(&ssl, server_name);
    if (ret != 0) {
        printf("  set_hostname 失败\n");
        goto exit;
    }
    printf("  SNI hostname: %s\n", server_name);

    /* 设置 I/O 回调 - 对应项目:
     * mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
     * 注意: 项目使用自定义 BIO（通过 IPC 转发给 AP），这里使用标准 socket */
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 步骤4: 建立 TCP 连接
     * 对应项目: mbedtls_ssl_socketconnect() (通过 AP 代理)
     */
    printf("[步骤4] 连接到 %s:%s ...\n", server_name, server_port);
    ret = mbedtls_net_connect(&server_fd, server_name, server_port,
                              MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("  连接失败: %s\n", err_buf);
        printf("  (可能需要网络访问)\n");
        goto exit;
    }
    printf("  ✓ TCP 连接建立\n");

    /*
     * 步骤5: 执行 TLS 握手
     * 对应项目:
     * while((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
     *     if(ret != WANT_READ && ret != WANT_WRITE && ret != CRYPTO_IN_PROGRESS)
     *         goto exit;
     * }
     */
    printf("[步骤5] 执行 TLS 握手...\n");
    printf("  证书验证过程:\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            printf("  握手失败: %s (-0x%04x)\n", err_buf, (unsigned int)-ret);

            /* 获取证书验证结果 - 对应项目:
             * flags = mbedtls_ssl_get_verify_result(&ssl); */
            uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
            if (flags != 0 && flags != (uint32_t)-1) {
                char vrfy_buf[256];
                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
                printf("%s\n", vrfy_buf);
            }
            goto exit;
        }
    }

    /* 打印连接信息 - 对应项目:
     * TLOGD("[ Protocol is %s ]", mbedtls_ssl_get_version(&ssl));
     * TLOGD("[ Ciphersuite is %s ]", mbedtls_ssl_get_ciphersuite(&ssl)); */
    printf("\n  ✓ TLS 握手成功!\n");
    printf("  协议版本: %s\n", mbedtls_ssl_get_version(&ssl));
    printf("  密码套件: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    ret = mbedtls_ssl_get_record_expansion(&ssl);
    if (ret >= 0) {
        printf("  记录扩展: %d bytes (每条记录的加密开销)\n", ret);
    }

    /* 打印服务器证书信息 */
    const mbedtls_x509_crt *peer_cert = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer_cert != NULL) {
        char cert_buf[512];
        mbedtls_x509_dn_gets(cert_buf, sizeof(cert_buf), &peer_cert->subject);
        printf("  服务器证书: %s\n", cert_buf);
    }

    /*
     * 步骤6: 发送数据
     */
    printf("\n[步骤6] 发送 HTTPS 请求...\n");
    printf("  请求: GET /get HTTP/1.1\n");
    ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request));
    if (ret <= 0) {
        printf("  发送失败: -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }
    printf("  ✓ 已发送 %d bytes\n", ret);

    /*
     * 步骤7: 接收响应
     */
    printf("[步骤7] 接收响应...\n");
    memset(response, 0, sizeof(response));
    int total_read = 0;
    do {
        ret = mbedtls_ssl_read(&ssl, response + total_read,
                               sizeof(response) - 1 - total_read);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
            break;
        }
        if (ret < 0) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            printf("  读取错误: %s\n", err_buf);
            break;
        }
        total_read += ret;
    } while (ret > 0 && total_read < (int)sizeof(response) - 1);

    response[total_read] = '\0';
    printf("  收到 %d bytes\n", total_read);
    /* 只打印前几行 */
    char *end = strstr((char *)response, "\r\n\r\n");
    if (end) {
        *end = '\0';
        printf("  响应头:\n%s\n  ...(body 省略)\n", response);
    } else if (total_read > 0) {
        printf("  响应 (前200字节):\n%.200s\n", response);
    }

    printf("\n  ✓ HTTPS 通信完成!\n");

    /*
     * 步骤8: 关闭连接
     * 对应项目: mbedtls_ssl_free(), mbedtls_net_free()
     */
exit:
    printf("\n[步骤8] 清理资源...\n");
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    printf("  ✓ 资源已释放\n");

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("完整 TLS 客户端流程:\n");
    printf("  1. mbedtls_ssl_config_defaults() - 设置角色和传输方式\n");
    printf("  2. mbedtls_ssl_conf_ca_chain()   - 加载 CA 证书\n");
    printf("  3. mbedtls_ssl_conf_authmode()   - 设置验证模式\n");
    printf("  4. mbedtls_ssl_setup()           - 应用配置\n");
    printf("  5. mbedtls_ssl_set_hostname()    - 设置 SNI\n");
    printf("  6. mbedtls_ssl_set_bio()         - 设置 I/O 回调\n");
    printf("  7. mbedtls_ssl_handshake()       - 执行握手\n");
    printf("  8. mbedtls_ssl_write/read()      - 收发数据\n");
    printf("  9. mbedtls_ssl_close_notify()    - 关闭通知\n");
    printf("══════════════════════════════════════════════\n");

    printf("\n✓ 示例运行完成\n");
    return 0;
}
