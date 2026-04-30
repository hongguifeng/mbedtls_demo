/**
 * 示例07：TLS 双向认证 (Mutual Authentication / mTLS)
 *
 * 本示例演示：
 * - 生成 CA + 服务器证书 + 客户端证书
 * - 启动本地 TLS 服务器（子线程）
 * - 客户端连接时提供客户端证书
 * - 双方互相验证身份
 *
 * 知识点：
 * 1. 单向认证: 只有客户端验证服务器 (普通 HTTPS)
 * 2. 双向认证: 服务器也要求客户端提供证书 (银行/支付/IoT)
 * 3. 服务器发送 CertificateRequest → 客户端回复 Certificate + CertificateVerify
 *
 * 在项目 task_mbedtls.c 中的实现：
 * ```c
 * if(client_authentication){
 *     ret = mbedtls_ssl_conf_own_cert(&conf_ext, &clicert_ext, &pkey_ext);
 * }
 * ```
 * - clicert_ext = AP03 EE 证书 + AP03_SUBCA 子 CA (证书链)
 * - pkey_ext = AP03 私钥
 * - client_authentication 由证书加载是否成功决定
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "psa/crypto.h"

/* 共享证书数据 */
static unsigned char ca_cert_pem[4096];
static unsigned char server_cert_pem[4096];
static unsigned char server_key_pem[4096];
static unsigned char client_cert_pem[4096];
static unsigned char client_key_pem[4096];

static volatile int server_ready = 0;
static const char *SERVER_PORT = "14433";

/**
 * 辅助：生成测试证书套件
 */
static int generate_test_certs(void)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context ca_key, srv_key, cli_key;
    mbedtls_x509write_cert write_cert;
    mbedtls_mpi serial;
    int ret;

    const char *pers = "cert_gen";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&srv_key);
    mbedtls_pk_init(&cli_key);
    mbedtls_mpi_init(&serial);

    printf("生成测试证书套件...\n");

    /* CA 密钥 (RSA-2048) */
    mbedtls_pk_setup(&ca_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ca_key), mbedtls_ctr_drbg_random,
                              &ctr_drbg, 2048, 65537);
    if (ret != 0) { printf("CA key gen failed\n"); goto exit; }

    /* Server 密钥 (ECC P-256) */
    mbedtls_pk_setup(&srv_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(srv_key),
                        mbedtls_ctr_drbg_random, &ctr_drbg);

    /* Client 密钥 (ECC P-256) - 对应项目 AP03 密钥 */
    mbedtls_pk_setup(&cli_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(cli_key),
                        mbedtls_ctr_drbg_random, &ctr_drbg);

    /* 1. CA 自签名证书 */
    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_lset(&serial, 1);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    mbedtls_x509write_crt_set_issuer_name(&write_cert, "CN=Demo CA,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_name(&write_cert, "CN=Demo CA,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_key(&write_cert, &ca_key);
    mbedtls_x509write_crt_set_issuer_key(&write_cert, &ca_key);
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&write_cert, 1, -1);
    mbedtls_x509write_crt_set_key_usage(&write_cert, MBEDTLS_X509_KU_KEY_CERT_SIGN);
    mbedtls_x509write_crt_pem(&write_cert, ca_cert_pem, sizeof(ca_cert_pem),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&write_cert);
    printf("  ✓ CA 证书: CN=Demo CA\n");

    /* 2. Server 证书 (由 CA 签名) */
    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_lset(&serial, 2);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    mbedtls_x509write_crt_set_issuer_name(&write_cert, "CN=Demo CA,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_name(&write_cert, "CN=localhost,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_key(&write_cert, &srv_key);
    mbedtls_x509write_crt_set_issuer_key(&write_cert, &ca_key);
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
    mbedtls_x509write_crt_set_key_usage(&write_cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    mbedtls_x509write_crt_pem(&write_cert, server_cert_pem, sizeof(server_cert_pem),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&write_cert);
    mbedtls_pk_write_key_pem(&srv_key, server_key_pem, sizeof(server_key_pem));
    printf("  ✓ Server 证书: CN=localhost (ECC P-256)\n");

    /* 3. Client 证书 (由 CA 签名) - 对应项目 AP03 证书 */
    mbedtls_x509write_crt_init(&write_cert);
    mbedtls_mpi_lset(&serial, 3);
    mbedtls_x509write_crt_set_serial(&write_cert, &serial);
    mbedtls_x509write_crt_set_validity(&write_cert, "20240101000000", "20261231235959");
    mbedtls_x509write_crt_set_issuer_name(&write_cert, "CN=Demo CA,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_name(&write_cert, "CN=Client-AP03,O=Tutorial,C=CN");
    mbedtls_x509write_crt_set_subject_key(&write_cert, &cli_key);
    mbedtls_x509write_crt_set_issuer_key(&write_cert, &ca_key);
    mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&write_cert, 0, 0);
    mbedtls_x509write_crt_set_key_usage(&write_cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    mbedtls_x509write_crt_pem(&write_cert, client_cert_pem, sizeof(client_cert_pem),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&write_cert);
    mbedtls_pk_write_key_pem(&cli_key, client_key_pem, sizeof(client_key_pem));
    printf("  ✓ Client 证书: CN=Client-AP03 (ECC P-256)\n");

exit:
    mbedtls_pk_free(&ca_key);
    mbedtls_pk_free(&srv_key);
    mbedtls_pk_free(&cli_key);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/**
 * TLS 服务器线程
 * 要求客户端提供证书（双向认证）
 */
static void *tls_server_thread(void *arg)
{
    (void)arg;
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert, srvcert;
    mbedtls_pk_context srvkey;
    int ret;
    unsigned char buf[1024];

    const char *pers = "tls_server";
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&srvkey);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    /* 加载证书 */
    mbedtls_x509_crt_parse(&cacert, ca_cert_pem, strlen((char *)ca_cert_pem) + 1);
    mbedtls_x509_crt_parse(&srvcert, server_cert_pem, strlen((char *)server_cert_pem) + 1);
    mbedtls_pk_parse_key(&srvkey, server_key_pem, strlen((char *)server_key_pem) + 1,
                         NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* 配置服务器 */
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* 关键：要求客户端证书 (双向认证) */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey);

    mbedtls_ssl_setup(&ssl, &conf);

    /* 监听 */
    ret = mbedtls_net_bind(&listen_fd, "localhost", SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("[Server] 绑定端口失败: -0x%04x\n", -ret);
        goto srv_exit;
    }

    server_ready = 1; /* 通知客户端可以连接了 */

    /* 接受连接 */
    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) goto srv_exit;

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* TLS 握手 */
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("[Server] 握手失败: -0x%04x\n", -ret);
            goto srv_exit;
        }
    }

    /* 验证客户端证书 */
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer) {
        char subject[256];
        mbedtls_x509_dn_gets(subject, sizeof(subject), &peer->subject);
        printf("[Server] 客户端证书验证通过: %s\n", subject);
    }

    /* 读取客户端消息 */
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        printf("[Server] 收到: \"%s\"\n", buf);

        /* 回复 */
        const char *reply = "Hello from mTLS server! Your identity is verified.";
        mbedtls_ssl_write(&ssl, (const unsigned char *)reply, strlen(reply));
    }

srv_exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&srvkey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return NULL;
}

/**
 * TLS 客户端 - 使用客户端证书进行双向认证
 * 对应项目 task_mbedtls.c 中的主流程
 */
static int tls_client_mutual_auth(void)
{
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert, clicert;
    mbedtls_pk_context clikey;
    int ret;
    unsigned char buf[1024];

    const char *pers = "tls_client_mtls";
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&clikey);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    /* 加载 CA 证书 (验证服务器) */
    printf("\n[Client] 加载 CA 证书...\n");
    mbedtls_x509_crt_parse(&cacert, ca_cert_pem, strlen((char *)ca_cert_pem) + 1);

    /* 加载客户端证书和私钥 - 对应项目:
     * MSCK_cert_and_priv_key_get("AP03", &dataCert, &sizeCert, &dataKey, &sizeKey);
     * mbedtls_x509_crt_parse(&clicert_ext, dataCertificate, sizeCertificate);
     * mbedtls_pk_parse_key(&pkey_ext, dataPrivateKey, sizePrivateKey, ...); */
    printf("[Client] 加载客户端证书和私钥 (模拟 AP03)...\n");
    ret = mbedtls_x509_crt_parse(&clicert, client_cert_pem,
                                 strlen((char *)client_cert_pem) + 1);
    if (ret != 0) {
        printf("[Client] 客户端证书加载失败\n");
        goto cli_exit;
    }

    ret = mbedtls_pk_parse_key(&clikey, client_key_pem,
                               strlen((char *)client_key_pem) + 1,
                               NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("[Client] 私钥加载失败\n");
        goto cli_exit;
    }

    /* 验证证书与私钥匹配 - 对应项目:
     * mbedtls_pk_check_pair(&clicert_ext.pk, &pkey_ext, ...) */
    ret = mbedtls_pk_check_pair(&clicert.pk, &clikey,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("[Client] ✗ 证书与私钥不匹配!\n");
        goto cli_exit;
    }
    printf("[Client] ✓ 证书与私钥匹配\n");

    /* 配置 SSL */
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    /* 关键：设置客户端证书 - 对应项目:
     * if(client_authentication){
     *     ret = mbedtls_ssl_conf_own_cert(&conf_ext, &clicert_ext, &pkey_ext);
     * } */
    printf("[Client] 配置客户端证书 (mbedtls_ssl_conf_own_cert)...\n");
    ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &clikey);
    if (ret != 0) {
        printf("[Client] mbedtls_ssl_conf_own_cert 失败: -0x%04x\n", -ret);
        goto cli_exit;
    }

    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, "localhost");

    /* 连接 */
    printf("[Client] 连接到 localhost:%s...\n", SERVER_PORT);
    ret = mbedtls_net_connect(&server_fd, "localhost", SERVER_PORT,
                              MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("[Client] 连接失败: -0x%04x\n", -ret);
        goto cli_exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* TLS 握手 (双向认证) */
    printf("[Client] 执行 TLS 握手 (双向认证)...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char err_buf[128];
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            printf("[Client] 握手失败: %s\n", err_buf);
            goto cli_exit;
        }
    }

    printf("[Client] ✓ 双向认证握手成功!\n");
    printf("[Client]   协议: %s\n", mbedtls_ssl_get_version(&ssl));
    printf("[Client]   密码套件: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    /* 验证服务器证书 */
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer) {
        char subject[256];
        mbedtls_x509_dn_gets(subject, sizeof(subject), &peer->subject);
        printf("[Client]   服务器证书: %s\n", subject);
    }

    /* 发送消息 */
    const char *msg = "Hello from mTLS client (AP03)!";
    printf("[Client] 发送: \"%s\"\n", msg);
    mbedtls_ssl_write(&ssl, (const unsigned char *)msg, strlen(msg));

    /* 接收回复 */
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        printf("[Client] 收到: \"%s\"\n", buf);
    }

    printf("\n✓ 双向认证通信完成!\n");

cli_exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_pk_free(&clikey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 07: TLS 双向认证 (mTLS)    ║\n");
    printf("╚══════════════════════════════════════════════╝\n");

    /* 初始化 PSA Crypto */
    psa_crypto_init();

    /* 生成测试证书 */
    int ret = generate_test_certs();
    if (ret != 0) {
        printf("证书生成失败\n");
        return 1;
    }

    /* 启动服务器线程 */
    printf("\n启动 TLS 服务器 (要求客户端证书)...\n");
    pthread_t server_tid;
    pthread_create(&server_tid, NULL, tls_server_thread, NULL);

    /* 等待服务器就绪 */
    while (!server_ready) {
        usleep(10000);
    }
    usleep(50000); /* 额外等待确保 accept 就绪 */

    /* 客户端连接 */
    tls_client_mutual_auth();

    /* 等待服务器线程结束 */
    pthread_join(server_tid, NULL);

    printf("\n");
    printf("══════════════════════════════════════════════\n");
    printf("双向认证要点:\n");
    printf("  - 服务器: mbedtls_ssl_conf_authmode(VERIFY_REQUIRED)\n");
    printf("  - 客户端: mbedtls_ssl_conf_own_cert(&conf, &clicert, &key)\n");
    printf("  - 密钥对验证: mbedtls_pk_check_pair()\n");
    printf("  - 项目模式: AP03 EE + AP03_SUBCA → 证书链\n");
    printf("  - 安全: 私钥存储在防篡改内存\n");
    printf("══════════════════════════════════════════════\n");

    return 0;
}
