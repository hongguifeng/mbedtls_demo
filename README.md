# mbedTLS 教程 —— 基于接口体系层次的实战开发

> 本教程按照 mbedTLS 的**接口设计层次**组织，从底层原语到顶层协议，逐层递进。
> 每个示例明确标注其所属层次、依赖关系和核心 API，帮助你建立完整的 API 心智模型。

---

## 目录

- [一、mbedTLS 接口体系总览](#一mbedtls-接口体系总览)
- [二、环境搭建](#二环境搭建)
- [三、L3 原语层：密码算法](#三l3-原语层密码算法)
  - [示例01：哈希/摘要算法](#示例01哈希摘要算法)
  - [示例02：对称加密 (AES)](#示例02对称加密-aes)
  - [示例03：非对称加密 (RSA)](#示例03非对称加密-rsa)
  - [示例04：椭圆曲线密码学 (ECC)](#示例04椭圆曲线密码学-ecc)
- [四、L5 证书层：X.509](#四l5-证书层x509)
  - [示例05：X.509 证书解析与验证](#示例05x509-证书解析与验证)
- [五、L6 协议层：TLS](#五l6-协议层tls)
  - [示例06：TLS 客户端基础连接](#示例06tls-客户端基础连接)
  - [示例07：TLS 双向认证 (mTLS)](#示例07tls-双向认证-mtls)
  - [示例08：自定义 BIO 回调](#示例08自定义-bio-回调)
- [六、TLS 协议原理](#六tls-协议原理)
- [七、PSA Crypto：现代接口体系](#七psa-crypto现代接口体系)
- [八、与项目代码的对应关系](#八与项目代码的对应关系)
- [九、常见问题](#九常见问题)

---

## 一、mbedTLS 接口体系总览

mbedTLS 的 API 设计遵循**自底向上的分层架构**，每一层只依赖其下层，形成清晰的依赖链。

### 层次架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│  L6  协议层 (Protocol)                                              │
│      ssl.h / ssl_ciphersuites.h / ssl_ticket.h / debug.h           │
│      ── TLS 1.2/1.3 完整协议栈：握手、记录层、Alert                  │
├─────────────────────────────────────────────────────────────────────┤
│  L5  证书层 (X.509 / PKCS)                                          │
│      x509_crt.h / x509_csr.h / x509_crl.h / pkcs12.h / pem.h       │
│      ── 证书解析、验证、证书链、PEM/DER 编解码                        │
├─────────────────────────────────────────────────────────────────────┤
│  L4  抽象层 (Abstraction)                                           │
│      cipher.h / md.h / pk.h                                        │
│      ── 算法无关的统一接口，运行时选择具体算法                         │
├─────────────────────────────────────────────────────────────────────┤
│  L3  原语层 (Primitives)                                            │
│      aes.h / gcm.h / rsa.h / ecp.h / sha256.h / chacha20.h ...     │
│      ── 具体算法实现，init → setkey → crypt → free                  │
├─────────────────────────────────────────────────────────────────────┤
│  L2  支撑层 (Support)                                               │
│      entropy.h / ctr_drbg.h / net_sockets.h / error.h / timing.h   │
│      ── 随机数生成、平台 I/O、错误处理                                │
├─────────────────────────────────────────────────────────────────────┤
│  L1  基础层 (Foundation)                                            │
│      bignum.h / platform.h / threading.h / asn1.h / constant_time.h│
│      ── 大数运算、平台抽象、线程锁、ASN.1 编解码                      │
└─────────────────────────────────────────────────────────────────────┘

  PSA Crypto (psa/crypto.h) ── 与 L3~L4 平行的现代接口体系
  ── 统一密钥管理 + 算法标识符 + 硬件驱动可替换
```

### 三个库的对应关系

```
libmbedcrypto  ←── L1 + L2 + L3 + L4 + PSA
libmbedx509    ←── L5 (依赖 libmbedcrypto)
libmbedtls     ←── L6 (依赖 libmbedx509 + libmbedcrypto)
```

### 核心设计原则

| 原则 | 说明 |
|------|------|
| **单一职责** | 每个头文件只负责一个算法或一个关注点 |
| **统一生命周期** | `init → setup/setkey → 操作 → free` 四段式 |
| **错误码统一** | 所有函数返回 `int`（0 成功，负值错误码），`mbedtls_strerror()` 转换 |
| **上下文分离** | 状态封装在 `*_context` 结构体中，无全局状态，天然线程安全 |
| **配置裁剪** | 通过 `mbedtls_config.h` 编译期开关（`MBEDTLS_AES_C` 等）裁剪功能 |

### 本教程示例与层次的映射

```
L3 原语层  ──→  01_hash (md.h/sha256.h)
               02_aes  (aes.h/gcm.h/cipher.h)
               03_rsa  (rsa.h/pk.h)
               04_ecc  (ecp.h/ecdsa.h/ecdh.h/pk.h)

L5 证书层  ──→  05_x509_parse (x509_crt.h/pk.h)

L6 协议层  ──→  06_tls_client (ssl.h/net_sockets.h)
               07_tls_mutual (ssl.h/x509_crt.h/pk.h)
               08_custom_bio (ssl.h + 自定义 I/O 回调)
```

---

## 二、环境搭建

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
./01_hash          # L3: 哈希算法
./02_aes           # L3: 对称加密
./03_rsa           # L3: RSA 非对称加密
./04_ecc           # L3: ECC 椭圆曲线
./05_x509_parse    # L5: 证书解析
./06_tls_client    # L6: TLS 客户端 (需要网络)
./07_tls_mutual    # L6: TLS 双向认证 (本地)
./08_custom_bio    # L6: 自定义 BIO (需要网络)
```

---

## 三、L3 原语层：密码算法

> **层次定位**：L3 是 mbedTLS 的核心算法层，每个头文件对应一个具体算法。
> 接口风格统一为 `init → setkey → crypt/sign/verify → free`。
> 本层不依赖 L4/L5/L6，可独立使用。

### 示例01：哈希/摘要算法

**所属层次**：L3 原语层（`sha256.h`）+ L4 抽象层（`md.h`）

**核心 API**：

| 层次 | 头文件 | 典型调用 |
|------|--------|----------|
| L3 底层 | `sha256.h` | `mbedtls_sha256_starts()` → `mbedtls_sha256_update()` → `mbedtls_sha256_finish()` |
| L4 抽象 | `md.h` | `mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)` → `mbedtls_md()` |

**概念**：哈希函数将任意长度输入映射为固定长度输出（摘要）。特性：
- 单向性：无法从摘要反推原文
- 抗碰撞：难以找到两个不同输入产生相同输出
- 雪崩效应：输入微小变化导致输出完全不同

**在 TLS 中的作用**：
- 证书指纹计算
- Finished 消息的 HMAC 计算
- HKDF 密钥派生（TLS 1.3 会话密钥生成）

**L3 vs L4 的选择**：
- 已知具体算法 → 用 L3（`sha256.h`），零开销
- 算法可配置/运行时选择 → 用 L4（`md.h`），多一层间接

→ 代码：[01_hash/main.c](01_hash/main.c)

---

### 示例02：对称加密 (AES)

**所属层次**：L3 原语层（`aes.h` / `gcm.h`）+ L4 抽象层（`cipher.h`）

**核心 API**：

| 层次 | 头文件 | 典型调用 |
|------|--------|----------|
| L3 底层 | `aes.h` | `mbedtls_aes_setkey_enc()` → `mbedtls_aes_crypt_cbc()` |
| L3 AEAD | `gcm.h` | `mbedtls_gcm_setkey()` → `mbedtls_gcm_crypt_and_tag()` |
| L4 抽象 | `cipher.h` | `mbedtls_cipher_setup()` → `mbedtls_cipher_setkey()` → `mbedtls_cipher_auth_encrypt()` |

**概念**：使用同一密钥进行加密和解密。三种模式对比：

| 模式 | 头文件 | 需要 IV | Padding | 认证 | TLS 用途 |
|------|--------|---------|---------|------|----------|
| CBC | `aes.h` | 16B | PKCS7 | ✗ | 旧版 TLS 1.0/1.1 |
| GCM | `gcm.h` | 12B | 无 | ✓ (AEAD) | **TLS 1.2/1.3 首选** |
| CTR | `aes.h` | 16B | 无 | ✗ | 流密码场景 |

**在 TLS 中的作用**：
- 握手完成后，双方协商出对称密钥
- 所有应用数据使用该密钥通过 AES-GCM 加密
- 每条记录使用不同的 IV（隐式序号 + 固定部分）

**L4 `cipher.h` 的典型用法**：
```c
mbedtls_cipher_context_t ctx;
mbedtls_cipher_init(&ctx);
mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));
mbedtls_cipher_setkey(&ctx, key, 256);
mbedtls_cipher_auth_encrypt(&ctx, plaintext, plaintext_len,
                            tag, tag_len, iv, iv_len, aad, aad_len, ciphertext);
mbedtls_cipher_free(&ctx);
```

→ 代码：[02_aes/main.c](02_aes/main.c)

---

### 示例03：非对称加密 (RSA)

**所属层次**：L3 原语层（`rsa.h`）+ L4 抽象层（`pk.h`）

**核心 API**：

| 层次 | 头文件 | 典型调用 |
|------|--------|----------|
| L3 底层 | `rsa.h` | `mbedtls_rsa_gen_key()` → `mbedtls_rsa_pkcs1_encrypt()` / `mbedtls_rsa_rsassa_pss_sign()` |
| L4 抽象 | `pk.h` | `mbedtls_pk_setup(&pk, MBEDTLS_PK_RSA)` → `mbedtls_pk_encrypt()` / `mbedtls_pk_sign()` |

**概念**：基于大整数分解难题的公钥密码体系。
- 公钥 (n, e)：加密 / 验签
- 私钥 (n, d)：解密 / 签名
- RSA 运算较慢，通常只用于：加密少量数据（会话密钥）、数字签名（签摘要而非原文）

**填充方案**：

| 用途 | 填充 | 函数 |
|------|------|------|
| 加密 | OAEP | `mbedtls_rsa_pkcs1_encrypt()` |
| 签名 | PSS | `mbedtls_rsa_rsassa_pss_sign()` |

**在 TLS 中的作用**：
- 证书中包含 RSA 公钥
- 服务器用 RSA 私钥签名证明身份（CertificateVerify）
- TLS 1.2 可选 RSA 密钥交换（TLS 1.3 已禁用）

**L4 `pk.h` 的价值**：统一 RSA/ECC/Ed25519 接口，上层代码无需关心具体算法：
```c
mbedtls_pk_context pk;
mbedtls_pk_init(&pk);
mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
mbedtls_pk_set_len(&pk, 2048);
mbedtls_pk_genkey(&pk, f_rng, p_rng);
/* 签名/验签/加密/解密 统一接口 */
mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, hash_len, sig, &sig_len, NULL, 0);
```

→ 代码：[03_rsa/main.c](03_rsa/main.c)

---

### 示例04：椭圆曲线密码学 (ECC)

**所属层次**：L3 原语层（`ecp.h` / `ecdsa.h` / `ecdh.h`）+ L4 抽象层（`pk.h`）

**核心 API**：

| 层次 | 头文件 | 典型调用 |
|------|--------|----------|
| L3 曲线 | `ecp.h` | `mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, ...)` |
| L3 签名 | `ecdsa.h` | `mbedtls_ecdsa_write_signature()` / `mbedtls_ecdsa_read_signature()` |
| L3 密钥交换 | `ecdh.h` | `mbedtls_ecdh_calc_secret()` |
| L4 抽象 | `pk.h` | `mbedtls_pk_setup(&pk, MBEDTLS_PK_ECKEY)` → 统一签名/验签 |

**概念**：基于椭圆曲线离散对数问题，相比 RSA：
- 256-bit ECC ≈ 3072-bit RSA 安全性
- 运算更快，密钥更短
- TLS 1.3 **仅**支持 ECDHE (Ephemeral) 密钥交换

**常用曲线**：

| 曲线 | 标识 | 用途 |
|------|------|------|
| P-256 (secp256r1) | `MBEDTLS_ECP_DP_SECP256R1` | TLS 最常用 |
| P-384 (secp384r1) | `MBEDTLS_ECP_DP_SECP384R1` | 更高安全性 |
| X25519 | `MBEDTLS_ECP_DP_CURVE25519` | TLS 1.3 推荐密钥交换 |

**在 TLS 中的作用**：
- ECDHE 密钥交换（TLS 1.3 唯一支持的密钥交换方式）
- ECDSA 证书签名（服务器/客户端 CertificateVerify）
- 证书中的公钥通常为 ECC 公钥

→ 代码：[04_ecc/main.c](04_ecc/main.c)

---

## 四、L5 证书层：X.509

> **层次定位**：L5 依赖 L3/L4（用 `pk.h` 操作公钥，用 `md.h` 计算摘要），
> 提供证书的解析、验证和证书链管理。

### 示例05：X.509 证书解析与验证

**所属层次**：L5 证书层（`x509_crt.h`）+ L4 抽象层（`pk.h`）

**核心 API**：

| 功能 | 函数 |
|------|------|
| 解析证书 | `mbedtls_x509_crt_parse()` |
| 设置信任锚 | `mbedtls_x509_crt_set_root_cas()` |
| 验证证书链 | `mbedtls_x509_crt_verify()` |
| 提取信息 | `mbedtls_x509_crt_info()` / `mbedtls_x509_string_to_name()` |
| 生成证书 | `mbedtls_x509write_crt_*()` |

**X.509 证书结构**：
```
Certificate v3
├── tbsCertificate
│   ├── version (v3)
│   ├── serialNumber
│   ├── signatureAlgorithm (如 sha256WithRSAEncryption)
│   ├── issuer (颁发者 DN)
│   ├── validity (notBefore / notAfter)
│   ├── subject (主体 DN)
│   ├── subjectPublicKeyInfo (算法 + 公钥)
│   └── extensions (SAN, KeyUsage, BasicConstraints...)
└── signatureValue (CA 私钥签名)
```

**证书链验证**：
```
Root CA (自签名，预置在信任库)
  └── Sub CA (由 Root CA 签名)
       └── EE 证书 (由 Sub CA 签名) ← 服务器/客户端使用
```

**验证过程**：
1. 签名验证：逐级验证签名直到信任锚点
2. 有效期检查（notBefore / notAfter）
3. 用途检查（Key Usage / Extended Key Usage）
4. 吊销检查（CRL / OCSP）

**在 TLS 中的作用**：
- 服务器在握手中发送证书链
- 客户端用 CA 证书验证服务器身份
- 双向认证时，服务器也验证客户端证书

→ 代码：[05_x509_parse/main.c](05_x509_parse/main.c)

---

## 五、L6 协议层：TLS

> **层次定位**：L6 是最顶层，组合 L3~L5 所有层实现完整 TLS 协议。
> 核心对象：`mbedtls_ssl_context`（连接状态）+ `mbedtls_ssl_config`（共享配置）。

### 示例06：TLS 客户端基础连接

**所属层次**：L6 协议层（`ssl.h`）+ L2 支撑层（`net_sockets.h`）+ L5（`x509_crt.h`）

**核心 API 生命周期**：

```
初始化阶段:
  mbedtls_ssl_config_init()          → 创建配置
  mbedtls_ssl_config_defaults()      → 设置默认值 (端点/模式/版本)
  mbedtls_ssl_conf_authmode()        → 设置验证模式
  mbedtls_ssl_conf_ca_chain()        → 加载 CA 证书 (L5)
  mbedtls_ssl_conf_rng()             → 设置随机数 (L2)
  mbedtls_ssl_init()                 → 创建连接上下文
  mbedtls_ssl_setup()                → 绑定配置到连接

连接阶段:
  mbedtls_net_connect()              → TCP 连接 (L2)
  mbedtls_ssl_set_bio()              → 绑定 I/O 回调
  mbedtls_ssl_set_hostname()         → SNI
  mbedtls_ssl_handshake()            → TLS 握手 (核心!)

数据阶段:
  mbedtls_ssl_write()                → 发送加密数据
  mbedtls_ssl_read()                 → 接收解密数据

关闭阶段:
  mbedtls_ssl_close_notify()         → 发送关闭通知
  mbedtls_ssl_free()                 → 释放连接
  mbedtls_ssl_config_free()          → 释放配置
```

**证书验证模式**：

| 模式 | 常量 | 说明 |
|------|------|------|
| 不验证 | `MBEDTLS_SSL_VERIFY_NONE` | 不安全，仅调试用 |
| 可选验证 | `MBEDTLS_SSL_VERIFY_OPTIONAL` | 验证但不强制 |
| 必须验证 | `MBEDTLS_SSL_VERIFY_REQUIRED` | **推荐**，验证失败则断开 |

**在 TLS 握手中的层次调用**：
```
mbedtls_ssl_handshake()
  ├── 生成随机数          → L2: ctr_drbg
  ├── 计算 Finished 消息  → L3: sha256 + L4: md
  ├── ECDHE 密钥交换      → L3: ecdh.h
  ├── 验证服务器证书      → L5: x509_crt_verify
  ├── 签名 CertificateVerify → L3: ecdsa / L4: pk
  └── 加密应用数据        → L3: aes-gcm / L4: cipher
```

→ 代码：[06_tls_client/main.c](06_tls_client/main.c)

---

### 示例07：TLS 双向认证 (mTLS)

**所属层次**：L6 协议层（`ssl.h`）+ L5（`x509_crt.h`）+ L4（`pk.h`）

**核心 API（在单向认证基础上增加）**：

```c
/* 客户端额外配置 */
mbedtls_ssl_conf_own_cert(&conf, &client_cert, &client_key);
/* 服务器端要求客户端证书 */
mbedtls_ssl_conf_authmode(&server_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
```

**概念**：
- 单向认证：只有客户端验证服务器（普通 HTTPS）
- 双向认证：服务器也要求客户端提供证书（银行/支付/IoT 场景）

**握手差异**（相比单向认证）：
```
服务器额外发送:  CertificateRequest (请求客户端证书)
客户端额外发送:  Certificate + CertificateVerify (证明持有私钥)
```

**客户端需要提供**：
- EE 证书（终端实体证书）
- 中间 CA 证书（证书链）
- 对应私钥

**在项目中的应用**：
```c
// task_mbedtls.c 中的双向认证逻辑
if(client_authentication){
    ret = mbedtls_ssl_conf_own_cert(&conf_ext, &clicert_ext, &pkey_ext);
}
```

→ 代码：[07_tls_mutual/main.c](07_tls_mutual/main.c)

---

### 示例08：自定义 BIO 回调

**所属层次**：L6 协议层（`ssl.h`）的 I/O 抽象机制

**核心 API**：

```c
/* 回调签名 */
typedef int (*mbedtls_ssl_send_function)(void *ctx, const unsigned char *buf, size_t len);
typedef int (*mbedtls_ssl_recv_function)(void *ctx, unsigned char *buf, size_t len);

/* 设置自定义 I/O */
mbedtls_ssl_set_bio(&ssl, &my_ctx, my_send, my_recv, my_rewrite);
```

**概念**：mbedTLS 通过 BIO (Basic I/O) 回调实现**传输层解耦**。
默认使用 `mbedtls_net_send/recv`（BSD socket），但可以替换为任何 I/O 实现：
- 嵌入式 IPC 通道
- 共享内存
- 自定义协议栈

**返回值约定**：
- 成功：返回实际发送/接收的字节数
- 失败：返回 `MBEDTLS_ERR_NET_*` 错误码
- 非阻塞：返回 `MBEDTLS_ERR_SSL_WANT_WRITE` / `MBEDTLS_ERR_SSL_WANT_READ`

**架构对比**：

```
项目架构 (SE + AP):
┌───────────────────┐   IPC (Event+IObuf)   ┌───────────────┐   Socket  ┌──────────┐
│ SE (mbedTLS)      │ ◄────────────────────► │ AP (proxy)    │ ◄───────► │ Server   │
│ custom_send/recv  │                        │ socket 代理   │           │          │
└───────────────────┘                        └───────────────┘           └──────────┘

本示例模拟:
┌───────────────────┐   Pipe (模拟IPC)       ┌───────────────┐   Socket  ┌──────────┐
│ TLS Client        │ ◄────────────────────► │ Proxy Thread  │ ◄───────► │ Server   │
│ custom_send/recv  │                        │ (模拟 AP)     │           │          │
└───────────────────┘                        └───────────────┘           └──────────┘
```

**在项目中的应用**：
```c
// task_mbedtls.c 的核心设计
mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) {
    send_se_cmd_on_channel_warning(SEND_DATA_SOCKET, buf, len);
    SYS_EvtGrpWait(evt_group, WARN_AND_MAINT_EVENT_RECEIVE, SYS_SUSPEND);
    ret = warningIObuf[0]*256 + warningIObuf[1];
    return ret;
}
```

→ 代码：[08_custom_bio/main.c](08_custom_bio/main.c)

---

## 六、TLS 协议原理

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
│  TCP/IP (或自定义 BIO)                     │
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

**TLS 1.3 关键变化**：
- 仅支持 ECDHE 密钥交换（前向保密）
- 移除了 RSA 密钥交换、CBC 模式、SHA-1
- 握手消息在加密通道中传输
- 密码套件简化为：`TLS_AES_128_GCM_SHA256` / `TLS_AES_256_GCM_SHA384`

### 密码学基础概念

| 概念 | 说明 | 对应层次 | 用途 |
|------|------|----------|------|
| **哈希 (Hash)** | 单向函数，固定长度输出 | L3: `sha256.h` | 完整性校验、签名、密钥派生 |
| **对称加密** | 加密解密使用同一密钥 | L3: `aes.h` / L4: `cipher.h` | 数据加密（AES-GCM） |
| **非对称加密** | 公钥加密/私钥解密 | L3: `rsa.h`/`ecp.h` / L4: `pk.h` | 密钥交换、数字签名 |
| **数字证书** | 绑定公钥与身份的文件 | L5: `x509_crt.h` | 身份认证 |
| **证书链** | Root CA → Sub CA → EE 证书 | L5: `x509_crt.h` | 信任传递 |
| **PKI** | 公钥基础设施 | L5 + L6 | 证书的颁发和管理体系 |

---

## 七、PSA Crypto：现代接口体系

> mbedTLS 3.x 引入的**新 API 体系**，与 legacy 接口平行，官方建议新代码优先使用。

### 设计目标

| 特性 | Legacy API | PSA Crypto API |
|------|-----------|----------------|
| 密钥管理 | 密钥字节直接暴露 | `psa_key_id_t` 标识，密钥不直接暴露 |
| 算法选择 | 枚举 + 函数名 | `psa_algorithm_t` 统一标识符 |
| 驱动替换 | 不支持 | `crypto_driver_*.h` 支持硬件/SE 后端 |
| 接口风格 | 每个算法一套函数 | 统一 `psa_cipher_*` / `psa_mac_*` / `psa_asymmetric_*` |

### 典型用法

```c
/* 初始化 */
psa_crypto_init();

/* 导入密钥 */
psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
psa_set_key_bits(&attr, 256);
psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
psa_key_id_t key;
psa_import_key(PSA_KEY_TYPE_AES, key_bytes, 32, &attr, &key);

/* 加密 */
psa_cipher_encrypt(key, PSA_ALG_AES_GCM, iv, iv_len,
                   aad, aad_len, plaintext, plaintext_len,
                   ciphertext, ciphertext_size, &ciphertext_length,
                   tag, tag_size, &tag_length);

/* 安全销毁 */
psa_destroy_key(key);
```

### 本教程中的 PSA 使用

- `06_tls_client` / `07_tls_mutual` / `08_custom_bio` 中调用 `psa_crypto_init()` 初始化 PSA 子系统
- TLS 握手内部通过 PSA 接口调用密码原语（3.x 内部实现已迁移到 PSA）

---

## 八、与项目代码的对应关系

| 教程示例 | 层次 | 项目代码位置 | 说明 |
|----------|------|-------------|------|
| 01_hash | L3/L4 | `psa_crypto_init()` | 哈希引擎初始化 |
| 02_aes | L3/L4 | TLS 记录层内部 | AES-GCM 数据加密 |
| 03_rsa | L3/L4 | `mbedtls_pk_parse_key()` | RSA 私钥解析 |
| 04_ecc | L3/L4 | `mbedtls_pk_parse_key()` + `mbedtls_pk_check_pair()` | ECC 密钥解析与验证 |
| 05_x509_parse | L5 | `mbedtls_x509_crt_parse()` | CA/客户端证书加载 |
| 06_tls_client | L6 | `mbedtls_ssl_handshake()` | 基础 TLS 握手 |
| 07_tls_mutual | L6 | `mbedtls_ssl_conf_own_cert()` | 客户端证书配置 |
| 08_custom_bio | L6 | `mbedtls_ssl_set_bio()` | 自定义 I/O 回调 |
| 验证回调 | L5/L6 | `my_verify()` | 证书验证逻辑 |

---

## 九、常见问题

### Q: 为什么项目中 TLShandshakeDone 区分两种接收模式？
握手阶段由 mbedTLS 库内部驱动 I/O（请求-应答模式），数据由 AP 网络代理直接返回。
应用数据阶段由命令循环驱动，AP 推送数据块到共享缓冲区，mbedTLS 的 recv 从缓冲区读取。

### Q: 为什么使用 PSA Crypto API？
mbedTLS 3.x 推荐使用 PSA Crypto API，它提供统一的密码操作接口，支持硬件加速器和安全存储后端。
TLS 握手内部已全面使用 PSA 接口调用密码原语。

### Q: TLS 1.2 vs TLS 1.3？
项目配置了 `mbedtls_ssl_conf_min_tls_version(TLS1_2)` / `max(TLS1_3)`，优先使用 TLS 1.3，但兼容 TLS 1.2。
TLS 1.3 仅支持 ECDHE + AES-GCM/ChaCha20-Poly1305，更安全且更快。

### Q: L3 底层 API 和 L4 抽象 API 如何选择？
- **性能敏感**（嵌入式、高频调用）→ 用 L3（`aes.h`、`sha256.h`），零间接开销
- **算法可配置**（运行时选择）→ 用 L4（`cipher.h`、`md.h`、`pk.h`）
- **新代码** → 优先用 PSA Crypto API

### Q: 如何裁剪 mbedTLS 以减小体积？
编辑 `mbedtls_config.h`，关闭不需要的模块：
```c
#undef MBEDTLS_RSA_C          /* 不需要 RSA */
#undef MBEDTLS_SSL_TLS_1_3    /* 不需要 TLS 1.3 */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED  /* 只保留 P-256 */
```
