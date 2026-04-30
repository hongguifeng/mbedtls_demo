# mbedTLS 教程 —— 从基础密码学到 TLS 通信开发

本教程参照 `se_pro_a/CTRL/modules/SecLink/task_mbedtls.c` 项目实际代码，由浅入深讲解如何使用 mbedTLS 进行 TLS 通信开发。

---

## 目录

1. [环境搭建](#环境搭建)
2. [示例01：哈希/摘要算法](#示例01哈希摘要算法)
3. [示例02：对称加密 (AES)](#示例02对称加密-aes)
4. [示例03：非对称加密 (RSA)](#示例03非对称加密-rsa)
5. [示例04：椭圆曲线密码学 (ECC)](#示例04椭圆曲线密码学-ecc)
6. [示例05：X.509 证书解析](#示例05x509-证书解析)
7. [示例06：TLS 客户端基础连接](#示例06tls-客户端基础连接)
8. [示例07：TLS 双向认证](#示例07tls-双向认证)
9. [示例08：自定义 BIO 回调](#示例08自定义-bio-回调)

---

## 环境搭建

### 依赖

- CMake >= 3.14
- GCC / Clang
- Git（用于自动下载 mbedTLS 源码）

### 编译

```bash
cd mbedtls_demo
mkdir build && cd build
cmake ..
make -j$(nproc)
```

首次编译会自动从 GitHub 下载 mbedTLS 3.6.0 LTS 源码。

### 运行示例

```bash
./01_hash
./02_aes
# ... 其他示例
```

---

## TLS 基础概念

### 什么是 TLS？

**TLS (Transport Layer Security)** 是一种加密通信协议，确保网络通信的：
- **机密性 (Confidentiality)**：数据加密，第三方无法窃听
- **完整性 (Integrity)**：数据不可被篡改
- **身份认证 (Authentication)**：确认通信对方身份

### TLS 协议分层

```
┌───────────────────────────────────────────┐
│  Application Data (HTTP, MQTT, etc.)      │
├───────────────────────────────────────────┤
│  TLS Record Protocol                      │
│  ┌─────────┬──────────┬────────────────┐  │
│  │Handshake│Alert     │Application Data│  │
│  │Protocol │Protocol  │Protocol        │  │
│  └─────────┴──────────┴────────────────┘  │
├───────────────────────────────────────────┤
│  TCP/IP                                   │
└───────────────────────────────────────────┘
```

### TLS 握手过程 (TLS 1.2)

```
客户端                                    服务器
  │                                         │
  │──── ClientHello ────────────────────────►│  (支持的密码套件、随机数)
  │                                         │
  │◄─── ServerHello ────────────────────────│  (选择的密码套件、随机数)
  │◄─── Certificate ────────────────────────│  (服务器证书)
  │◄─── ServerKeyExchange ──────────────────│  (密钥交换参数)
  │◄─── CertificateRequest (可选) ─────────│  (请求客户端证书 → 双向认证)
  │◄─── ServerHelloDone ───────────────────│
  │                                         │
  │──── Certificate (可选) ─────────────────►│  (客户端证书)
  │──── ClientKeyExchange ──────────────────►│  (预主密钥)
  │──── CertificateVerify (可选) ──────────►│  (证书验证签名)
  │──── ChangeCipherSpec ───────────────────►│
  │──── Finished ───────────────────────────►│
  │                                         │
  │◄─── ChangeCipherSpec ───────────────────│
  │◄─── Finished ───────────────────────────│
  │                                         │
  │◄═══ 加密通信开始 ═══════════════════════►│
```

### TLS 1.3 的改进

TLS 1.3 将握手从 2-RTT 压缩到 **1-RTT**（甚至 0-RTT）：

```
客户端                                    服务器
  │                                         │
  │──── ClientHello + KeyShare ─────────────►│
  │                                         │
  │◄─── ServerHello + KeyShare ─────────────│
  │◄─── EncryptedExtensions ────────────────│  (加密开始!)
  │◄─── Certificate ────────────────────────│
  │◄─── CertificateVerify ─────────────────│
  │◄─── Finished ───────────────────────────│
  │                                         │
  │──── Finished ───────────────────────────►│
  │                                         │
  │◄═══ 加密通信 ═══════════════════════════►│
```

### 密码学基础概念

| 概念 | 说明 | 用途 |
|------|------|------|
| **哈希 (Hash)** | 单向函数，固定长度输出 | 数据完整性校验、数字签名 |
| **对称加密** | 加密解密使用同一密钥 | 数据加密（AES-GCM） |
| **非对称加密** | 公钥加密/私钥解密 | 密钥交换、数字签名 |
| **数字证书** | 绑定公钥与身份的文件 | 身份认证 |
| **证书链** | Root CA → Sub CA → EE 证书 | 信任传递 |
| **PKI** | 公钥基础设施 | 证书的颁发和管理体系 |

### mbedTLS 库结构

```
libmbedcrypto  ── 底层密码算法 (AES, RSA, ECC, Hash, RNG)
libmbedx509    ── X.509 证书解析和验证
libmbedtls     ── TLS 协议实现 (握手、记录层、alert)
```

---

## 示例01：哈希/摘要算法

**概念**：哈希函数将任意长度的输入映射为固定长度的输出（摘要）。特性：
- 单向性：无法从摘要反推原文
- 抗碰撞：难以找到两个不同输入产生相同输出
- 雪崩效应：输入微小变化导致输出完全不同

**在 TLS 中的作用**：证书指纹、消息认证码 (HMAC)、密钥派生 (HKDF)

→ 代码：[01_hash/main.c](01_hash/main.c)

---

## 示例02：对称加密 (AES)

**概念**：使用同一密钥进行加密和解密。AES-GCM 是 TLS 中最常用的对称加密模式，提供：
- 加密（机密性）
- 认证标签 (Authentication Tag)（完整性）
- 关联数据认证 (AEAD)

**在 TLS 中的作用**：握手完成后，所有应用数据使用协商的对称密钥加密

→ 代码：[02_aes/main.c](02_aes/main.c)

---

## 示例03：非对称加密 (RSA)

**概念**：使用密钥对（公钥/私钥），公钥加密的数据只有私钥能解密，私钥签名的数据用公钥验证。

**在 TLS 中的作用**：
- 证书中包含公钥
- 服务器用私钥签名证明身份
- TLS 1.2 的 RSA 密钥交换

→ 代码：[03_rsa/main.c](03_rsa/main.c)

---

## 示例04：椭圆曲线密码学 (ECC)

**概念**：基于椭圆曲线数学的公钥密码体系，相比 RSA：
- 更短的密钥长度达到同等安全性（256-bit ECC ≈ 3072-bit RSA）
- 更快的运算速度
- TLS 1.3 **仅**支持 ECDHE 密钥交换

**在项目中的应用**：`task_mbedtls.c` 使用 `mbedtls_pk_parse_key` 解析 ECC 私钥，用于客户端双向认证。

→ 代码：[04_ecc/main.c](04_ecc/main.c)

---

## 示例05：X.509 证书解析

**概念**：X.509 证书包含：
- 主体信息 (Subject)
- 颁发者 (Issuer)
- 公钥
- 有效期
- 签名（由 CA 私钥签名）

**证书链验证**：
```
Root CA (自签名，受信任)
  └── Sub CA (由 Root CA 签名)
       └── EE 证书 (由 Sub CA 签名) ← 服务器/客户端使用
```

**在项目中的应用**：
- `cacert_ext` = 服务器 Sub CA 证书
- `clicert_ext` = 客户端 EE 证书 + Sub CA（证书链）
- `my_verify()` 回调处理证书验证（时间未设置时忽略过期）

→ 代码：[05_x509_parse/main.c](05_x509_parse/main.c)

---

## 示例06：TLS 客户端基础连接

**概念**：最基本的 TLS 单向认证连接：
1. 加载 CA 证书（验证服务器身份）
2. 配置 SSL 上下文
3. 建立 TCP 连接
4. 执行 TLS 握手
5. 收发加密数据
6. 关闭连接

**对应项目代码**：`task_mbedtls.c` 中 L420-660 的握手流程

→ 代码：[06_tls_client/main.c](06_tls_client/main.c)

---

## 示例07：TLS 双向认证 (Mutual Authentication)

**概念**：服务器不仅验证自己的身份，还要求客户端提供证书证明身份。

**在项目中的应用**：
```c
// task_mbedtls.c 中的双向认证逻辑
if(client_authentication){
    ret = mbedtls_ssl_conf_own_cert(&conf_ext, &clicert_ext, &pkey_ext);
}
```
客户端需要提供：
- EE 证书 (AP03)
- Sub CA 证书 (AP03_SUBCA) 
- 对应私钥

→ 代码：[07_tls_mutual/main.c](07_tls_mutual/main.c)

---

## 示例08：自定义 BIO 回调

**概念**：mbedTLS 允许替换默认的 socket I/O，使用自定义回调进行数据收发。这是嵌入式系统的关键技术——当 SE 没有直接网络访问时，通过 IPC 委托给 AP。

**在项目中的应用**：
```c
// task_mbedtls.c 的核心设计
mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
```
- `mbedtls_net_send` → 通过 IPC 通道发送给 AP → AP 通过 socket 发送到服务器
- `mbedtls_net_recv` → 通过 IPC 请求 AP 读取 socket 数据

→ 代码：[08_custom_bio/main.c](08_custom_bio/main.c)

---

## 与项目代码的对应关系

| 教程示例 | 项目代码位置 | 说明 |
|----------|-------------|------|
| 05_x509_parse | `mbedtls_x509_crt_parse()` 调用 | CA/客户端证书加载 |
| 06_tls_client | `mbedtls_ssl_handshake()` | 基础 TLS 握手 |
| 07_tls_mutual | `mbedtls_ssl_conf_own_cert()` | 客户端证书配置 |
| 08_custom_bio | `mbedtls_ssl_set_bio()` | 自定义 I/O 回调 |
| 验证回调 | `my_verify()` | 证书验证逻辑 |

---

## 常见问题

### Q: 为什么项目中 TLShandshakeDone 区分两种接收模式？
握手阶段由 mbedTLS 库内部驱动 I/O（请求-应答模式），数据由 AP 网络代理直接返回。
应用数据阶段由命令循环驱动，AP 推送数据块到共享缓冲区，mbedTLS 的 recv 从缓冲区读取。

### Q: 为什么使用 PSA Crypto API？
mbedTLS 3.x 推荐使用 PSA Crypto API，它提供统一的密码操作接口，支持硬件加速器和安全存储后端。

### Q: TLS 1.2 vs TLS 1.3？
项目配置了 `mbedtls_ssl_conf_min_tls_version(TLS1_2)` / `max(TLS1_3)`，优先使用 TLS 1.3，但兼容 TLS 1.2。
