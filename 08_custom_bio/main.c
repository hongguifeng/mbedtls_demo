/**
 * 示例08：自定义 BIO 回调 (Custom I/O)
 *
 * 本示例演示 mbedTLS 最强大的特性之一：自定义 I/O 回调。
 * 这使得 mbedTLS 可以运行在没有标准 socket API 的环境中。
 *
 * 本示例模拟项目 task_mbedtls.c 的核心设计：
 * - SE 没有直接网络访问
 * - 通过 IPC (pipe) 将 TLS 数据转发给 "AP" 进程
 * - "AP" 负责实际的 socket 通信
 *
 * 架构对比：
 *
 * 项目架构：
 * ┌───────────────────┐   IPC (Event+warningIObuf)  ┌───────────────┐   Socket  ┌──────────┐
 * │ SE (mbedTLS_task) │ ◄─────────────────────────► │ AP (task_seclink)│ ◄──────► │ Server   │
 * │ mbedtls_net_send  │                             │ Socket proxy   │          │          │
 * │ mbedtls_net_recv  │                             │                │          │          │
 * └───────────────────┘                             └───────────────┘          └──────────┘
 *
 * 本示例模拟：
 * ┌───────────────────┐   Pipe (模拟IPC)           ┌───────────────┐   Socket  ┌──────────┐
 * │ TLS Client        │ ◄─────────────────────────► │ Proxy Thread  │ ◄──────► │ Server   │
 * │ custom_send       │                             │ (模拟 AP)      │          │          │
 * │ custom_recv       │                             │                │          │          │
 * └───────────────────┘                             └───────────────┘          └──────────┘
 *
 * 知识点：
 * 1. mbedtls_ssl_set_bio() 设置自定义收发函数
 * 2. 发送回调签名: int (*f_send)(void *ctx, const unsigned char *buf, size_t len)
 * 3. 接收回调签名: int (*f_recv)(void *ctx, unsigned char *buf, size_t len)
 * 4. 返回值: 成功返回字节数, 失败返回 MBEDTLS_ERR_NET_* 错误码
 * 5. 该机制使 mbedTLS 完全与传输层解耦
 *
 * 在项目中的体现：
 * ```c
 * // task_mbedtls.c
 * mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
 *
 * int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) {
 *     send_se_cmd_on_channel_warning(SEND_DATA_SOCKET, buf, len);
 *     SYS_EvtGrpWait(evt_group, WARN_AND_MAINT_EVENT_RECEIVE, SYS_SUSPEND);
 *     ret = warningIObuf[0]*256 + warningIObuf[1];
 *     return ret;
 * }
 * ```
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
#include "mbedtls/platform.h"

/*
 * ═══════════════════════════════════════════
 * IPC 通道模拟 (对应项目中的 warningIObuf + 事件组)
 * ═══════════════════════════════════════════
 */

/* 使用 pipe 模拟 SE ↔ AP 的 IPC 通道 */
static int ipc_to_proxy[2];   /* SE → Proxy (AP): TLS 数据发送请求 */
static int ipc_from_proxy[2]; /* Proxy (AP) → SE: 网络数据返回 */

/* IPC 消息类型 (模拟项目中的 channel 命令) */
#define IPC_CMD_SEND  0x01  /* 对应 SEND_DATA_SOCKET */
#define IPC_CMD_RECV  0x02  /* 对应 RCV_DATA_SOCKET */
#define IPC_CMD_CLOSE 0x03  /* 对应 CLOSE_SOCKET */

/* IPC 消息格式 */
typedef struct {
    uint8_t cmd;
    uint16_t len;
    /* data follows */
} __attribute__((packed)) ipc_msg_header_t;

/*
 * ═══════════════════════════════════════════
 * 自定义 BIO 回调 (对应项目 mbedtls_net_send/recv)
 * ═══════════════════════════════════════════
 */

/**
 * 自定义发送回调
 * 对应项目中:
 *   int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) {
 *       send_se_cmd_on_channel_warning(SEND_DATA_SOCKET, buf, len);
 *       SYS_EvtGrpWait(..., WARN_AND_MAINT_EVENT_RECEIVE, SYS_SUSPEND);
 *       ret = warningIObuf[0]*256 + warningIObuf[1];
 *       return ret;
 *   }
 */
static int custom_send(void *ctx, const unsigned char *buf, size_t len)
{
    (void)ctx;
    ipc_msg_header_t hdr;
    int ret_val;

    /* 发送请求到 Proxy (模拟 send_se_cmd_on_channel_warning) */
    hdr.cmd = IPC_CMD_SEND;
    hdr.len = (uint16_t)len;
    write(ipc_to_proxy[1], &hdr, sizeof(hdr));
    write(ipc_to_proxy[1], buf, len);

    /* 等待 Proxy 返回结果 (模拟 SYS_EvtGrpWait) */
    read(ipc_from_proxy[0], &ret_val, sizeof(ret_val));

    return ret_val; /* 返回实际发送字节数 */
}

/**
 * 自定义接收回调
 * 对应项目中:
 *   int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len) {
 *       data[0] = len/256; data[1] = len%256;
 *       send_se_cmd_on_channel_warning(RCV_DATA_SOCKET, data, 2);
 *       SYS_EvtGrpWait(..., WARN_AND_MAINT_EVENT_RECEIVE, SYS_SUSPEND);
 *       memcpy(buf, warningIObuf, warningIOLen);
 *       return warningIOLen;
 *   }
 */
static int custom_recv(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    ipc_msg_header_t hdr;
    int recv_len;

    /* 发送接收请求到 Proxy (告知期望长度) */
    hdr.cmd = IPC_CMD_RECV;
    hdr.len = (uint16_t)len;
    write(ipc_to_proxy[1], &hdr, sizeof(hdr));

    /* 等待 Proxy 返回数据 (模拟 SYS_EvtGrpWait + memcpy from warningIObuf) */
    read(ipc_from_proxy[0], &recv_len, sizeof(recv_len));
    if (recv_len > 0) {
        read(ipc_from_proxy[0], buf, recv_len);
    }

    return recv_len;
}

/*
 * ═══════════════════════════════════════════
 * Proxy 线程 (模拟 AP 的网络代理角色)
 * ═══════════════════════════════════════════
 */

static const char *proxy_server = "httpbin.org";
static const char *proxy_port = "443";

static void *proxy_thread(void *arg)
{
    (void)arg;
    mbedtls_net_context real_fd;
    ipc_msg_header_t hdr;
    unsigned char data_buf[8192];
    int ret;

    mbedtls_net_init(&real_fd);

    printf("[Proxy/AP] 建立到 %s:%s 的 TCP 连接...\n", proxy_server, proxy_port);
    ret = mbedtls_net_connect(&real_fd, proxy_server, proxy_port,
                              MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("[Proxy/AP] 连接失败: -0x%04x\n", -ret);
        /* 通知客户端连接失败 */
        int err = MBEDTLS_ERR_NET_CONNECT_FAILED;
        write(ipc_from_proxy[1], &err, sizeof(err));
        return NULL;
    }
    printf("[Proxy/AP] ✓ TCP 连接建立\n");

    /* 主循环：处理来自 SE 的 IPC 请求 */
    while (1) {
        ssize_t n = read(ipc_to_proxy[0], &hdr, sizeof(hdr));
        if (n <= 0) break;

        switch (hdr.cmd) {
            case IPC_CMD_SEND: {
                /* 从 IPC 读取数据 */
                read(ipc_to_proxy[0], data_buf, hdr.len);
                /* 通过 socket 发送 */
                ret = (int)write(real_fd.fd, data_buf, hdr.len);
                /* 返回发送字节数给 SE */
                write(ipc_from_proxy[1], &ret, sizeof(ret));
                break;
            }
            case IPC_CMD_RECV: {
                /* 从 socket 接收数据 */
                int want_len = hdr.len;
                if (want_len > (int)sizeof(data_buf)) want_len = sizeof(data_buf);
                ret = (int)read(real_fd.fd, data_buf, want_len);
                if (ret < 0) ret = 0;
                /* 返回数据给 SE */
                write(ipc_from_proxy[1], &ret, sizeof(ret));
                if (ret > 0) {
                    write(ipc_from_proxy[1], data_buf, ret);
                }
                break;
            }
            case IPC_CMD_CLOSE:
                goto proxy_done;
        }
    }

proxy_done:
    mbedtls_net_free(&real_fd);
    printf("[Proxy/AP] 连接已关闭\n");
    return NULL;
}

/*
 * ═══════════════════════════════════════════
 * TLS 客户端 (使用自定义 BIO)
 * ═══════════════════════════════════════════
 */

static int tls_client_with_custom_bio(void)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    int ret;
    char err_buf[128];
    unsigned char response[2048];

    const char *pers = "custom_bio_demo";
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    /* 加载系统 CA */
    ret = mbedtls_x509_crt_parse_file(&cacert, "/etc/ssl/certs/ca-certificates.crt");
    if (ret < 0) {
        ret = mbedtls_x509_crt_parse_file(&cacert, "/etc/pki/tls/certs/ca-bundle.crt");
    }

    /* 配置 SSL */
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (cacert.version != 0) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, proxy_server);

    /*
     * 关键：使用自定义 BIO 回调代替标准 socket
     * 对应项目:
     *   mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
     *
     * 参数说明:
     * - ctx (NULL): 传给回调的上下文指针（项目中是 &server_fd，但实际未使用）
     * - f_send (custom_send): 发送回调
     * - f_recv (custom_recv): 接收回调
     * - f_recv_timeout (NULL): 带超时的接收回调（可选）
     */
    printf("[SE/Client] 设置自定义 BIO 回调 (mbedtls_ssl_set_bio)\n");
    printf("  f_send = custom_send → 通过 IPC 发送到 Proxy/AP\n");
    printf("  f_recv = custom_recv → 通过 IPC 从 Proxy/AP 接收\n\n");
    mbedtls_ssl_set_bio(&ssl, NULL, custom_send, custom_recv, NULL);

    /* TLS 握手 - 所有数据通过 IPC → Proxy → Socket */
    printf("[SE/Client] 执行 TLS 握手 (通过 IPC 代理)...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            printf("[SE/Client] 握手失败: %s\n", err_buf);
            goto client_exit;
        }
    }

    printf("[SE/Client] ✓ TLS 握手成功! (通过自定义 BIO)\n");
    printf("[SE/Client]   协议: %s\n", mbedtls_ssl_get_version(&ssl));
    printf("[SE/Client]   密码套件: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

    /* 发送 HTTP 请求 - 数据通过 custom_send → IPC → Proxy → Socket → Server */
    const char *request =
        "GET /get HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Connection: close\r\n"
        "\r\n";

    printf("\n[SE/Client] 发送 HTTPS 请求 (经过 IPC 代理)...\n");
    ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request));
    if (ret <= 0) {
        printf("[SE/Client] 发送失败\n");
        goto client_exit;
    }
    printf("[SE/Client] ✓ 已发送 %d bytes\n", ret);

    /* 接收响应 */
    printf("[SE/Client] 接收响应...\n");
    int total = 0;
    do {
        ret = mbedtls_ssl_read(&ssl, response + total, sizeof(response) - 1 - total);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret <= 0) break;
        total += ret;
    } while (total < (int)sizeof(response) - 1);

    response[total] = '\0';
    printf("[SE/Client] 收到 %d bytes\n", total);
    /* 只打印 HTTP 状态行 */
    char *eol = strstr((char *)response, "\r\n");
    if (eol) {
        *eol = '\0';
        printf("[SE/Client] 响应: %s\n", response);
    }

    printf("\n✓ 自定义 BIO 通信完成!\n");
    printf("  整个 TLS 通信都通过 IPC → Proxy 转发，与项目架构一致\n");

client_exit:
    /* 通知 proxy 关闭 */
    {
        ipc_msg_header_t hdr = {IPC_CMD_CLOSE, 0};
        write(ipc_to_proxy[1], &hdr, sizeof(hdr));
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret >= 0 ? 0 : ret;
}

int main(void)
{
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  mbedTLS 教程 - 08: 自定义 BIO 回调 (Custom I/O)          ║\n");
    printf("║  模拟项目 task_mbedtls.c 的 SE ↔ AP 代理架构             ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    printf("\n");
    printf("原理说明:\n");
    printf("  mbedtls_ssl_set_bio() 允许替换默认的 socket I/O\n");
    printf("  项目中 SE 没有网络栈，通过 IPC 将数据转发给 AP 处理\n");
    printf("  本示例用 pipe 模拟这一 IPC 机制\n");
    printf("\n");
    printf("数据流:\n");
    printf("  mbedtls_ssl_write() → custom_send() → pipe → Proxy → socket → Server\n");
    printf("  mbedtls_ssl_read()  ← custom_recv() ← pipe ← Proxy ← socket ← Server\n");
    printf("\n");

    /* 创建 IPC 通道 (pipe) */
    if (pipe(ipc_to_proxy) < 0 || pipe(ipc_from_proxy) < 0) {
        printf("创建 pipe 失败\n");
        return 1;
    }

    /* 启动 Proxy 线程 (模拟 AP) */
    pthread_t proxy_tid;
    pthread_create(&proxy_tid, NULL, proxy_thread, NULL);
    usleep(100000); /* 等待连接建立 */

    /* 运行 TLS 客户端 */
    tls_client_with_custom_bio();

    /* 清理 */
    pthread_join(proxy_tid, NULL);
    close(ipc_to_proxy[0]);
    close(ipc_to_proxy[1]);
    close(ipc_from_proxy[0]);
    close(ipc_from_proxy[1]);

    printf("\n");
    printf("══════════════════════════════════════════════════════════════\n");
    printf("自定义 BIO 要点:\n");
    printf("  1. mbedtls_ssl_set_bio(ssl, ctx, f_send, f_recv, NULL)\n");
    printf("  2. f_send 返回实际发送字节数（或负数错误码）\n");
    printf("  3. f_recv 返回实际接收字节数（或负数错误码）\n");
    printf("  4. ctx 指针传递给回调，可以是任何上下文\n");
    printf("  5. 适用场景: 嵌入式 IPC、串口、USB、共享内存等\n");
    printf("\n");
    printf("项目代码对应:\n");
    printf("  custom_send ≈ mbedtls_net_send (send_se_cmd_on_channel_warning)\n");
    printf("  custom_recv ≈ mbedtls_net_recv (SYS_EvtGrpWait + warningIObuf)\n");
    printf("  pipe        ≈ warningIObuf + event_group IPC 机制\n");
    printf("  proxy       ≈ AP 的 response_to_se_command_signal()\n");
    printf("══════════════════════════════════════════════════════════════\n");

    return 0;
}
