# mbedTLS 教程 —— 从 Legacy API 到 PSA Crypto 的完整实战

> 本教程覆盖 **mbedTLS 3.6 LTS**（Legacy API）和 **mbedTLS 4.2**（PSA Crypto API + 新架构），
> 按照接口设计层次组织，从底层原语到顶层协议，逐层递进。
> 每个示例明确标注其所属层次、依赖关系和核心 API，帮助你建立完整的 API 心智模型。

---

## 目录结构

```
mbedtls_demo/
├── build.sh                  # 总构建脚本（依次构建两个子项目）
├── CMakeLists.txt            # 顶层说明（不直接编译）
├── README.md                 # 本文件
├── mbedtls_36/               # ── mbedTLS 3.6.0 LTS (Legacy API) ──
│   ├── CMakeLists.txt
│   ├── build.sh
│   ├── 01_hash/              # L3: 哈希/摘要算法
│   ├── 02_aes/               # L3: 对称加密 (AES)
│   ├── 03_rsa/               # L3: 非对称加密 (RSA)
│   ├── 04_ecc/               # L3: 椭圆曲线密码学
│   ├── 05_x509_parse/        # L5: X.509 证书解析
│   ├── 06_tls_client/        # L6: TLS 客户端
│   ├── 07_tls_mutual/        # L6: TLS 双向认证
│   ├── 08_custom_bio/        # L6: 自定义 BIO 回调
│   └── 09_embedded_stm32/    # 嵌入式: STM32F407 + FreeRTOS 交叉编译（Legacy API）
└── mbedtls_42/               # ── mbedTLS 4.2.0 (PSA Crypto API) ──
    ├── CMakeLists.txt
    ├── build.sh
    ├── 09_psa_hash/          # PSA: 哈希/摘要
    ├── 10_psa_cipher/        # PSA: 对称加密 (AES-CBC/CTR)
    ├── 11_psa_aead/          # PSA: AEAD (AES-GCM)
    ├── 12_psa_mac/           # PSA: MAC (HMAC/CMAC)
    ├── 13_psa_asymmetric/    # PSA: 非对称签名 (ECC/RSA)
    ├── 14_psa_kdf/           # PSA: 密钥派生 (HKDF/ECDH)
    ├── 15_psa_key_mgmt/      # PSA: 密钥管理
    └── 16_embedded_stm32/    # 嵌入式: STM32F407 + FreeRTOS 交叉编译（PSA API）
```

---

## 目录

- [一、mbedTLS 接口体系总览](#一mbedtls-接口体系总览)
- [二、环境搭建与构建](#二环境搭建与构建)
- [三、L3 原语层：密码算法 (3.6)](#三l3-原语层密码算法-36)
  - [示例01：哈希/摘要算法](#示例01哈希摘要算法)
  - [示例02：对称加密 (AES)](#示例02对称加密-aes)
  - [示例03：非对称加密 (RSA)](#示例03非对称加密-rsa)
  - [示例04：椭圆曲线密码学 (ECC)](#示例04椭圆曲线密码学-ecc)
- [四、L5 证书层：X.509 (3.6)](#四l5-证书层x509-36)
  - [示例05：X.509 证书解析与验证](#示例05x509-证书解析与验证)
- [五、L6 协议层：TLS (3.6)](#五l6-协议层tls-36)
  - [示例06：TLS 客户端基础连接](#示例06tls-客户端基础连接)
  - [示例07：TLS 双向认证 (mTLS)](#示例07tls-双向认证-mtls)
  - [示例08：自定义 BIO 回调](#示例08自定义-bio-回调)
- [六、TLS 协议原理](#六tls-协议原理)
- [七、mbedTLS 4.x 架构变革](#七mbedtls-4x-架构变革)
  - [7.1 从单体到模块化：tf-psa-crypto 拆分](#71-从单体到模块化tf-psa-crypto-拆分)
  - [7.2 目录结构对比](#72-目录结构对比)
  - [7.3 构建系统变化](#73-构建系统变化)
  - [7.4 3.x → 4.x API 兼容性](#74-3x--4x-api-兼容性)
- [八、PSA Crypto API 深入 (4.2)](#八psa-crypto-api-深入-42)
  - [8.1 PSA 设计哲学](#81-psa-设计哲学)
  - [8.2 密钥管理模型](#82-密钥管理模型)
  - [8.3 算法标识符体系](#83-算法标识符体系)
  - [8.4 操作生命周期模式](#84-操作生命周期模式)
  - [示例09：PSA 哈希/摘要](#示例09psa-哈希摘要)
  - [示例10：PSA 对称加密](#示例10psa-对称加密)
  - [示例11：PSA AEAD](#示例11psa-aead)
  - [示例12：PSA MAC](#示例12psa-mac)
  - [示例13：PSA 非对称签名](#示例13psa-非对称签名)
  - [示例14：PSA KDF](#示例14psa-kdf)
  - [示例15：PSA 密钥管理](#示例15psa-密钥管理)
- [九、接口层设计：硬件驱动可替换性](#九接口层设计硬件驱动可替换性)
- [十、与项目代码的对应关系](#十与项目代码的对应关系)
- [十一、嵌入式集成：裁剪与交叉编译 (STM32 + FreeRTOS)](#十一嵌入式集成裁剪与交叉编译-stm32--freertos)
  - [11.1 可替换接口总览](#111-可替换接口总览)
  - [11.2 裁剪方法论：3.6 vs 4.2](#112-裁剪方法论36-vs-42)
  - [11.3 交叉编译工具链与 CMake](#113-交叉编译工具链与-cmake)
  - [11.4 FreeRTOS 集成要点](#114-freertos-集成要点)
  - [示例09：3.6 Legacy API 嵌入式固件](#示例0936-legacy-api-嵌入式固件)
  - [示例16：4.2 PSA API 嵌入式固件](#示例1642-psa-api-嵌入式固件)
  - [11.5 体积数据与裁剪效果](#115-体积数据与裁剪效果)
- [十二、常见问题](#十二常见问题)

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

## 二、环境搭建与构建

### 依赖

- CMake >= 3.14
- GCC / Clang
- Git（用于自动下载 mbedTLS 源码及子模块）

### 编译

两个子项目**独立构建**，互不干扰：

```bash
# 方式一：总脚本（依次构建两个子项目）
./build.sh

# 方式二：分别构建
cd mbedtls_36 && ./build.sh    # mbedTLS 3.6.0 LTS
cd mbedtls_42 && ./build.sh    # mbedTLS 4.2.0 PSA Crypto
```

首次编译会自动从 GitHub 下载对应版本的 mbedTLS 源码（4.2 包含 `tf-psa-crypto` 和 `framework` 子模块）。

### 运行示例

```bash
# mbedTLS 3.6 (Legacy API)
cd mbedtls_36/build
./01_hash          # L3: 哈希算法
./02_aes           # L3: 对称加密
./03_rsa           # L3: RSA 非对称加密
./04_ecc           # L3: ECC 椭圆曲线
./05_x509_parse    # L5: 证书解析
./06_tls_client    # L6: TLS 客户端 (需要网络)
./07_tls_mutual    # L6: TLS 双向认证 (本地)
./08_custom_bio    # L6: 自定义 BIO (需要网络)

# mbedTLS 4.2 (PSA Crypto API)
cd ../../mbedtls_42/build
./09_psa_hash        # PSA: 哈希/摘要
./10_psa_cipher      # PSA: 对称加密
./11_psa_aead        # PSA: AEAD (AES-GCM)
./12_psa_mac         # PSA: MAC (HMAC/CMAC)
./13_psa_asymmetric  # PSA: 非对称签名
./14_psa_kdf         # PSA: 密钥派生
./15_psa_key_mgmt    # PSA: 密钥管理
```

---

## 三、L3 原语层：密码算法 (3.6)

> **层次定位**：L3 是 mbedTLS 的核心算法层，每个头文件对应一个具体算法。
> 接口风格统一为 `init → setkey → crypt/sign/verify → free`。
> 本层不依赖 L4/L5/L6，可独立使用。
> **注意**：以下示例基于 mbedTLS 3.6 Legacy API，4.x 中对应功能请使用 PSA Crypto API（见第八章）。

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

## 四、L5 证书层：X.509 (3.6)

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

## 五、L6 协议层：TLS (3.6)

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

## 七、mbedTLS 4.x 架构变革

### 7.1 从单体到模块化：tf-psa-crypto 拆分

mbedTLS 4.x 进行了**重大架构重构**，将密码学核心库从主仓库中拆分为独立的 `tf-psa-crypto` 子模块：

```
mbedTLS 3.x (单体):                    mbedTLS 4.x (模块化):
┌─────────────────────┐               ┌──────────────────────────────────┐
│   mbedtls/          │               │   mbedtls/                       │
│   ├── include/      │               │   ├── include/mbedtls/           │
│   │   ├── mbedtls/  │               │   │   ├── ssl.h                  │
│   │   └── psa/      │               │   │   ├── x509_crt.h             │
│   ├── library/      │               │   │   └── ... (TLS/X.509)        │
│   │   ├── aes.c     │               │   ├── library/                   │
│   │   ├── rsa.c     │               │   │   ├── ssl_msg.c              │
│   │   ├── ecp.c     │               │   │   └── x509_crt.c             │
│   │   └── ...       │               │   │                              │
│   └── tests/        │               │   ├── tf-psa-crypto/  ◄── 子模块 │
└─────────────────────┘               │   │   ├── include/psa/           │
                                      │   │   │   ├── crypto.h           │
                                      │   │   │   ├── crypto_values.h    │
                                      │   │   │   └── crypto_sizes.h     │
                                      │   │   ├── include/mbedtls/       │
                                      │   │   │   ├── md.h (legacy)      │
                                      │   │   │   ├── pk.h (legacy)      │
                                      │   │   │   └── platform.h         │
                                      │   │   ├── core/                  │
                                      │   │   │   ├── crypto.c           │
                                      │   │   │   ├── cipher.c           │
                                      │   │   │   └── ...                │
                                      │   │   └── drivers/builtin/       │
                                      │   │       ├── aes.c              │
                                      │   │       ├── rsa.c              │
                                      │   │       └── ecp.c              │
                                      │   └── framework/      ◄── 子模块 │
                                      │       ├── include/mbedtls/       │
                                      │       │   ├── build_info.h       │
                                      │       │   └── config_psa.h       │
                                      │       └── ...                    │
                                      └──────────────────────────────────┘
```

**拆分动机**：
1. **独立演进**：PSA Crypto 可以独立于 TLS 发布，支持非 TLS 场景（IoT 安全芯片、HSM）
2. **驱动可替换性**：`tf-psa-crypto/drivers/` 目录允许替换底层实现（硬件加速器、SE）
3. **最小化部署**：嵌入式设备可以只部署 `tfpsacrypto`，不需要完整的 TLS 栈
4. **跨项目复用**：TF-PSA-Crypto 可独立用于 TrustZone、OP-TEE 等安全环境

### 7.2 目录结构对比

| 内容 | 3.x 位置 | 4.x 位置 |
|------|----------|----------|
| PSA 头文件 | `include/psa/crypto.h` | `tf-psa-crypto/include/psa/crypto.h` |
| Legacy 密码头文件 | `include/mbedtls/aes.h`（公开） | `tf-psa-crypto/drivers/builtin/include/mbedtls/private/aes.h`（**私有**，不可依赖，见 7.4） |
| TLS/X.509 头文件 | `include/mbedtls/ssl.h` | `include/mbedtls/ssl.h`（不变） |
| 密码实现 | `library/aes.c` | `tf-psa-crypto/drivers/builtin/src/aes.c` |
| PSA 核心 | `library/psa_crypto.c` | `tf-psa-crypto/core/crypto.c` |
| 构建配置 | `include/mbedtls/mbedtls_config.h` | `framework/include/mbedtls/mbedtls_config.h` + `tf-psa-crypto/include/psa/crypto_config.h` |

### 7.3 构建系统变化

| 项目 | 3.x | 4.x |
|------|-----|-----|
| 密码库目标名 | `mbedcrypto` | **`tfpsacrypto`** |
| X.509 库目标名 | `mbedx509` | `mbedx509`（不变） |
| TLS 库目标名 | `mbedtls` | `mbedtls`（不变） |
| 依赖关系 | `mbedtls → mbedx509 → mbedcrypto` | `mbedtls → mbedx509 → tfpsacrypto` |
| 子模块 | 无 | `tf-psa-crypto` + `framework` |
| 配置头文件 | `mbedtls_config.h` | `mbedtls_config.h` + `crypto_config.h`（PSA 专用） |

**CMake 链接示例**：
```cmake
# 3.x
target_link_libraries(my_app mbedtls mbedx509 mbedcrypto)

# 4.x - 仅密码学（不需要 TLS）
target_link_libraries(my_app tfpsacrypto)

# 4.x - 完整 TLS
target_link_libraries(my_app mbedtls mbedx509 tfpsacrypto)
```

### 7.4 3.x → 4.x API 兼容性

**结论：不完全兼容。** 4.0 是一个**破坏性（breaking）大版本**，官方明确说明与 3.x 不兼容，
需要修改代码才能迁移（官方迁移指南：`docs/4.0-migration-guide.md`）。

#### 主要变化

**1. 大部分 legacy 密码学 API 被删除**（最大的坑）

- `mbedtls/aes.h`、`mbedtls/rsa.h`、`mbedtls/ecp.h`、`mbedtls/cipher.h`、
  `mbedtls/md.h`（legacy 版）、`mbedtls/sha256.h`、`mbedtls/pk.h`（legacy 版）等头文件
  **不再公开提供**，被移到了 `tf-psa-crypto/drivers/builtin/include/mbedtls/private/`
  （私有头文件，官方声明可能随时移除或修改，不可依赖）
- 官方要求改用 **PSA API**：`psa/crypto.h`
  （`psa_hash_compute`、`psa_cipher_encrypt`、`psa_aead_encrypt`、`psa_sign_message` 等）
- 配置宏从 `MBEDTLS_RSA_C`、`MBEDTLS_AES_C` 等改为 `PSA_WANT_xxx`

**2. TLS / X.509 API 大部分保留，但有调整**

- `mbedtls/ssl.h`、`mbedtls/x509*.h` 仍在，常用接口（`mbedtls_ssl_*`、`mbedtls_x509_crt_*`）基本可用
- 删除的函数：
  - `mbedtls_ssl_conf_rng()`（现在强制使用 PSA RNG）
  - `mbedtls_ssl_conf_min_version()` / `mbedtls_ssl_conf_max_version()`
    （改用 `mbedtls_ssl_conf_min_tls_version()` / `mbedtls_ssl_conf_max_tls_version()`）
  - `mbedtls_ssl_conf_curves()`、`mbedtls_ssl_conf_sig_hashes()`（改用 `mbedtls_ssl_conf_sig_algs()`）
  - DHE 相关函数（TLS 1.2 不再支持 DHE）
- 很多 legacy 错误码被移除，改为返回 PSA 错误码

**3. 构建系统**

- 只支持 CMake，Makefile / Visual Studio 工程文件已移除

**4. 兼容辅助**

- 提供 `mbedtls/compat-3-crypto.h`：把部分 3.x 错误码映射到 PSA 错误码，方便过渡
- 3.x 里的 `compat-2.x.h`（2.x 兼容层）在 4.x 中被删除

#### 对本教程示例的影响

| 3.x 示例 | 使用的 legacy API | 4.x 迁移方式 |
|----------|-------------------|--------------|
| 01_hash | `mbedtls_md_*` | `psa_hash_compute()`（示例09） |
| 02_aes | `mbedtls_cipher_*` / `mbedtls_aes_*` | `psa_cipher_*`（示例10）/ `psa_aead_*`（示例11） |
| 03_rsa | `mbedtls_rsa_*` / `mbedtls_pk_*` | `psa_sign_message()` / `psa_verify_message()`（示例13） |
| 04_ecc | `mbedtls_ecp_*` / `mbedtls_ecdsa_*` | `psa_import_key()` + `psa_sign_message()`（示例13/15） |
| 05_x509_parse | `mbedtls_x509_crt_*` | 基本可直接使用（X.509 API 保留） |
| 06~08 TLS | `mbedtls_ssl_*` | 基本可直接使用，注意上述被删除的函数 |

> **迁移建议**：如果代码只用到 TLS/X.509 接口，4.x 基本平滑（少量函数改名/删除）；
> 如果直接调用了 legacy 密码学 API（AES/MD/RSA/ECC 等），则必须迁移到 PSA API。

---

## 八、PSA Crypto API 深入 (4.2)

> PSA (Platform Security Architecture) Crypto API 是 ARM 定义的**标准化密码接口规范**。
> mbedTLS 4.x 中，PSA 成为**首选接口**，Legacy API 保留但不再推荐用于新代码。

### 8.1 PSA 设计哲学

| 特性 | Legacy API (3.x) | PSA Crypto API (4.x) |
|------|-----------------|---------------------|
| **密钥管理** | 密钥字节直接暴露给应用 | `psa_key_id_t` 标识，密钥材料由 PSA 存储管理 |
| **算法选择** | 枚举 + 函数名 (`mbedtls_aes_crypt_cbc`) | `psa_algorithm_t` 统一标识符 |
| **驱动替换** | 不支持（编译时绑定） | `crypto_driver_*.h` 运行时可替换后端 |
| **接口风格** | 每个算法一套函数 | 按操作类型分组：`psa_cipher_*` / `psa_mac_*` / `psa_aead_*` |
| **策略检查** | 无（应用自行保证） | 创建时设定 usage flags，运行时强制检查 |
| **硬件支持** | 需手动集成 | 标准驱动接口，SE/HSM 透明替换 |

### 8.2 密钥管理模型

PSA 的核心创新是**统一密钥管理**。所有密钥（对称/非对称）通过 `psa_key_id_t`（uint32_t）标识：

```
┌─────────────────────────────────────────────────────────────┐
│                    PSA Key Storage                           │
│                                                             │
│  key_id=1: AES-256, ENCRYPT|DECRYPT, GCM                   │
│  key_id=2: ECC P-256, SIGN|VERIFY, ECDSA-SHA256            │
│  key_id=3: HMAC-SHA256, SIGN_MESSAGE|VERIFY_MESSAGE         │
│  key_id=4: RSA-2048, SIGN|VERIFY, PKCS1v15-SHA256          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  密钥材料（不直接暴露给应用层）                       │    │
│  │  - 内存后端：psa_crypto_driver_key_store             │    │
│  │  - 持久化后端：文件系统 / NVS / SE                   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
         ▲                    ▲                    ▲
         │                    │                    │
   psa_generate_key()   psa_import_key()   psa_export_key()
```

**密钥属性 (`psa_key_attributes_t`)**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `type` | `psa_key_type_t` | 密钥类型（AES/RSA/ECC/HMAC/...） |
| `bits` | `size_t` | 密钥长度（位） |
| `usage_flags` | `psa_key_usage_flags_t` | 允许的操作位掩码 |
| `algorithm` | `psa_algorithm_t` | 允许的算法 |
| `policy` | `psa_key_policy_t` | 完整策略（含生命周期） |

**使用标志 (`psa_key_usage_flags_t`)**：

| 标志 | 值 | 适用类型 |
|------|-----|----------|
| `PSA_KEY_USAGE_EXPORT` | 0x0001 | 所有密钥（`psa_export_key` 必需） |
| `PSA_KEY_USAGE_COPY` | 0x0002 | 所有密钥 |
| `PSA_KEY_USAGE_ENCRYPT` | 0x0100 | 对称密钥 |
| `PSA_KEY_USAGE_DECRYPT` | 0x0200 | 对称密钥 |
| `PSA_KEY_USAGE_SIGN_MESSAGE` | 0x0400 | MAC/非对称私钥 |
| `PSA_KEY_USAGE_VERIFY_MESSAGE` | 0x0800 | MAC/非对称公钥 |
| `PSA_KEY_USAGE_ENCRYPT` + `DECRYPT` | 0x0300 | AES (CBC/GCM) |
| `PSA_KEY_USAGE_SIGN_HASH` | 0x1000 | 非对称私钥 |
| `PSA_KEY_USAGE_VERIFY_HASH` | 0x2000 | 非对称公钥 |
| `PSA_KEY_USAGE_DERIVE` | 0x4000 | KDF 输入密钥 |

### 8.3 算法标识符体系

PSA 使用**位域编码**的 `psa_algorithm_t`（uint32_t）统一标识所有算法：

```
psa_algorithm_t 结构 (32 位):
┌──────────┬──────────────────┬──────────────────────────────┐
│ 类别      │ 短算法            │ 长算法 (hash/signature 变体)   │
│ (4 bits) │ (12 bits)        │ (16 bits)                    │
└──────────┴──────────────────┴──────────────────────────────┘
  0x02=HASH  0x03=MAC  0x04=CIPHER  0x05=AEAD  0x06=ASYM_SIGN  0x08=KDF

示例 (取自 crypto_values.h):
PSA_ALG_GCM                          = 0x05500200  (AEAD: AES-GCM)
PSA_ALG_CBC_PKCS7                    = 0x04404100  (CIPHER: CBC + PKCS7)
PSA_ALG_CTR                          = 0x04c01000  (CIPHER: CTR)
PSA_ALG_HMAC(PSA_ALG_SHA_256)       = 0x03800009  (MAC: HMAC-SHA256)
PSA_ALG_ECDSA(PSA_ALG_SHA_256)      = 0x06000609  (ASYM: ECDSA-SHA256)
PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256) = 0x06000209
PSA_ALG_HKDF(PSA_ALG_SHA_256)       = 0x08000109  (KDF: HKDF-SHA256)
PSA_ALG_ECDH                         = 0x09020000  (KDF: ECDH)
```

**密钥类型标识符 (`psa_key_type_t`)**：

| 宏 | 值 | 说明 |
|----|-----|------|
| `PSA_KEY_TYPE_AES` | 0x2400 | AES 对称密钥 |
| `PSA_KEY_TYPE_HMAC` | 0x1100 | HMAC 密钥 |
| `PSA_KEY_TYPE_DERIVE` | 0x1200 | KDF 输入/共享秘密密钥 |
| `PSA_KEY_TYPE_RSA_KEY_PAIR` | 0x7001 | RSA 密钥对 |
| `PSA_KEY_TYPE_ECC_KEY_PAIR(family)` | 0x7100 \| family | ECC 密钥对（按族） |
| `PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)` | 0x4100 \| family | ECC 公钥（按族） |

**ECC 曲线指定方式（4.x 重要变化）**：

```c
/* 3.x: 每条曲线一个宏 */
MBEDTLS_ECP_DP_SECP256R1

/* 4.x PSA: 族 + 位数 */
psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
psa_set_key_bits(&attrs, 256);  /* P-256 */
/* 或 psa_set_key_bits(&attrs, 384); → P-384 */

/* ECC 族: */
PSA_ECC_FAMILY_SECP_R1          = 0x12  (NIST P-192/224/256/384/521)
PSA_ECC_FAMILY_MONTGOMERY       = 0x41  (X25519, X448)
PSA_ECC_FAMILY_TWISTED_EDWARDS  = 0x42  (Ed25519, Ed448)
```

### 8.4 操作生命周期模式

PSA 操作分为**一次性 (one-shot)** 和**流式 (streaming/multipart)** 两种模式：

```
一次性模式 (适合小数据):
  psa_hash_compute(alg, input, len, hash, size, &hlen)
  psa_cipher_encrypt(key, alg, pt, ptlen, ct, ctsz, &ctlen)   /* 无 IV/tag 参数 */
  psa_mac_sign(key, alg, input, inlen, mac, msize, &mlen)

流式模式 (适合大数据/分块处理):
  psa_hash_setup(&op, alg)          → 初始化操作上下文
  psa_hash_update(&op, data, len)   → 可多次调用，逐块输入
  psa_hash_finish(&op, hash, sz, &hlen) → 完成，输出结果
  psa_hash_abort(&op)               → 或中止（释放资源）

通用模式:
  setup → [update]* → finish/abort
```

**操作上下文结构体**：

| 操作类型 | 上下文 | 初始化宏 |
|----------|--------|----------|
| 哈希 | `psa_hash_operation_t` | `PSA_HASH_OPERATION_INIT` |
| 对称加密 | `psa_cipher_operation_t` | `PSA_CIPHER_OPERATION_INIT` |
| AEAD | `psa_aead_operation_t` | `PSA_AEAD_OPERATION_INIT` |
| MAC | `psa_mac_operation_t` | `PSA_MAC_OPERATION_INIT` |
| KDF | `psa_key_derivation_operation_t` | `PSA_KEY_DERIVATION_OPERATION_INIT` |

---

### 示例09：PSA 哈希/摘要

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 模式 | 函数 |
|------|------|
| 一次性 | `psa_hash_compute(alg, input, len, hash, size, &hlen)` |
| 流式初始化 | `psa_hash_setup(&op, alg)` |
| 流式更新 | `psa_hash_update(&op, data, len)` |
| 流式完成 | `psa_hash_finish(&op, hash, size, &hlen)` |
| 比较 | `psa_hash_compare(alg, input, len, hash, hlen)` |
| 中止 | `psa_hash_abort(&op)` |

**与 Legacy API 对比**：

```c
/* 3.x Legacy (md.h) */
mbedtls_md_context_t ctx;
mbedtls_md_init(&ctx);
mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
mbedtls_md_starts(&ctx);
mbedtls_md_update(&ctx, data, len);
mbedtls_md_finish(&ctx, hash);
mbedtls_md_free(&ctx);

/* 4.x PSA */
psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
psa_hash_setup(&op, PSA_ALG_SHA_256);
psa_hash_update(&op, data, len);
psa_hash_finish(&op, hash, sizeof(hash), &hlen);
psa_hash_abort(&op);  /* 即使 finish 成功也建议调用 */
```

**要点**：
- `PSA_ALG_SHA_256` / `PSA_ALG_SHA_384` / `PSA_ALG_SHA_512` 直接标识算法
- 无需 `mbedtls_md_info_from_type()` 间接查找
- `psa_hash_compare()` 提供常量时间比较，防止时序攻击

→ 代码：[mbedtls_42/09_psa_hash/main.c](mbedtls_42/09_psa_hash/main.c)

---

### 示例10：PSA 对称加密

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 功能 | 函数 |
|------|------|
| 加密初始化 | `psa_cipher_encrypt_setup(&op, key, alg)` |
| 解密初始化 | `psa_cipher_decrypt_setup(&op, key, alg)` |
| 设置 IV | `psa_cipher_set_iv(&op, iv, ivlen)` |
| 生成 IV | `psa_cipher_generate_iv(&op, iv, size, &ivlen)` |
| 更新 | `psa_cipher_update(&op, in, inlen, out, outsize, &outlen)` |
| 完成 | `psa_cipher_finish(&op, out, outsize, &outlen)` |
| 中止 | `psa_cipher_abort(&op)` |

**与 Legacy API 对比**：

```c
/* 3.x Legacy (cipher.h) */
mbedtls_cipher_context_t ctx;
mbedtls_cipher_init(&ctx);
mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC));
mbedtls_cipher_setkey(&ctx, key, 256);
mbedtls_cipher_set_iv(&ctx, iv, 16);
mbedtls_cipher_crypt(&ctx, pt, ptlen, ct, ctlen);
mbedtls_cipher_free(&ctx);

/* 4.x PSA */
psa_key_id_t key;  /* 密钥通过 ID 引用，不直接暴露 */
psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
psa_cipher_encrypt_setup(&op, key, PSA_ALG_CBC_PKCS7);
psa_cipher_set_iv(&op, iv, 16);
psa_cipher_update(&op, pt, ptlen, ct, ctsize, &outlen);
psa_cipher_finish(&op, ct + outlen, ctsize - outlen, &finlen);
psa_cipher_abort(&op);
```

**要点**：
- 密钥通过 `psa_key_id_t` 引用，不直接传递字节
- `PSA_ALG_CBC_PKCS7` / `PSA_ALG_CTR` 标识模式+填充
- 4.x 中 `psa_cipher_encrypt_setup()` 需要传入 key（3.x 是 `setup` + `setkey` 两步）
- **若需 `psa_export_key()` 导出密钥，密钥策略必须包含 `PSA_KEY_USAGE_EXPORT`**，否则返回 `PSA_ERROR_NOT_PERMITTED`（本示例的"密钥导入/导出"演示即依赖此标志）

→ 代码：[mbedtls_42/10_psa_cipher/main.c](mbedtls_42/10_psa_cipher/main.c)

---

### 示例11：PSA AEAD

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 模式 | 函数 |
|------|------|
| 一次性加密 | `psa_aead_encrypt(key, alg, nonce, nlen, aad, aadlen, pt, ptlen, ct, ctsz, &ctlen)` |
| 一次性解密 | `psa_aead_decrypt(key, alg, nonce, nlen, aad, aadlen, ct, ctlen, pt, ptsz, &ptlen)` |
| 流式初始化 | `psa_aead_encrypt_setup(&op, key, alg)` / `psa_aead_decrypt_setup(&op, key, alg)` |
| 设置 Nonce | `psa_aead_set_nonce(&op, nonce, nlen)` |
| 设置 AAD | `psa_aead_update_ad(&op, aad, aadlen)` |
| 更新 | `psa_aead_update(&op, in, inlen, out, outsz, &outlen)` |
| 完成（加密，Tag 独立） | `psa_aead_finish(&op, out, outsz, &outlen, tag, tagsz, &taglen)` |
| 完成（解密，验证 Tag） | `psa_aead_verify(&op, pt, ptsz, &ptlen, tag, taglen)` |

**与 Legacy API 对比**：

```c
/* 3.x Legacy (gcm.h) */
mbedtls_gcm_context_t ctx;
mbedtls_gcm_init(&ctx);
mbedtls_gcm_setkey(&ctx, key, 256);
mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt, ptlen,
                          iv, ivlen, aad, aadlen, ct, tag, taglen);
mbedtls_gcm_free(&ctx);

/* 4.x PSA (一次性) */
psa_aead_encrypt(key, PSA_ALG_GCM, nonce, 12,
                 aad, aadlen, pt, ptlen, ct, ctsize, &ctlen);
/* 注意: GCM 的 tag 追加在密文末尾，ctlen = ptlen + taglen */

/* 4.x PSA (流式加密) */
psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
psa_aead_encrypt_setup(&op, key, PSA_ALG_GCM);
psa_aead_set_nonce(&op, nonce, 12);
psa_aead_update_ad(&op, aad, aadlen);          /* 4.x 中 AAD 用 update_ad */
size_t ct_len = 0;
for (size_t i = 0; i < nchunks; i++) {
    size_t out_len = 0;                        /* 每次调用独立累加 */
    psa_aead_update(&op, chunk[i], clen[i],
                    ct + ct_len, ctsize - ct_len, &out_len);
    ct_len += out_len;
}
uint8_t tag[16]; size_t tag_len = 0, fin_len = 0;
psa_aead_finish(&op, ct + ct_len, ctsize - ct_len, &fin_len,
                tag, sizeof(tag), &tag_len);   /* 4.x 中 tag 是独立参数 */
ct_len += fin_len + tag_len;
memcpy(ct + ct_len, tag, tag_len);

/* 4.x PSA (流式解密)：密文去掉末尾 tag 后 update，再用 verify 校验 tag */
psa_aead_operation_t dop = PSA_AEAD_OPERATION_INIT;
psa_aead_decrypt_setup(&dop, key, PSA_ALG_GCM);
psa_aead_set_nonce(&dop, nonce, 12);
psa_aead_update_ad(&dop, aad, aadlen);
size_t pt_len = 0;
psa_aead_update(&dop, ct, ct_len - tag_len, pt, ptsize, &pt_len);
psa_aead_verify(&dop, pt + pt_len, ptsize - pt_len, &pt_len,
                ct + ct_len - tag_len, tag_len);
```

**要点**：
- `PSA_ALG_GCM` 默认 tag 长度 16 字节，可用 `PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 12)` 缩短
- GCM 的 nonce 推荐 12 字节（96 bit）
- **4.x 流式 `finish` 的 tag 是独立参数**（3.x 是追加在密文末尾），解密用 `psa_aead_verify()` 校验 tag
- **`psa_aead_update()` 的 `*output_length` 只返回本次调用的输出长度**，分块时必须用独立变量累加，不能复用总长度变量（否则输出指针错位）
- **缩短 tag 时，密钥策略必须用 `psa_set_key_algorithm()` 设为对应的 `PSA_ALG_AEAD_WITH_SHORTENED_TAG(...)`**，否则加密返回 `PSA_ERROR_NOT_PERMITTED`

→ 代码：[mbedtls_42/11_psa_aead/main.c](mbedtls_42/11_psa_aead/main.c)

---

### 示例12：PSA MAC

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 模式 | 函数 |
|------|------|
| 一次性签名 | `psa_mac_sign(key, alg, input, inlen, mac, msize, &mlen)` |
| 一次性验证 | `psa_mac_verify(key, alg, input, inlen, mac, mlen)` |
| 流式签名初始化 | `psa_mac_sign_setup(&op, key, alg)` |
| 流式验证初始化 | `psa_mac_verify_setup(&op, key, alg)` |
| 更新 | `psa_mac_update(&op, data, len)` |
| 签名完成 | `psa_mac_sign_finish(&op, mac, msize, &mlen)` |
| 验证完成 | `psa_mac_verify_finish(&op, mac, mlen)` |

**支持的 MAC 算法**：

| 算法宏 | 说明 | 密钥类型 |
|--------|------|----------|
| `PSA_ALG_HMAC(PSA_ALG_SHA_256)` | HMAC-SHA256 | `PSA_KEY_TYPE_HMAC` |
| `PSA_ALG_HMAC(PSA_ALG_SHA_384)` | HMAC-SHA384 | `PSA_KEY_TYPE_HMAC` |
| `PSA_ALG_CMAC_AES_128` | AES-128-CMAC | `PSA_KEY_TYPE_AES` (128-bit) |
| `PSA_ALG_CMAC_AES_256` | AES-256-CMAC | `PSA_KEY_TYPE_AES` (256-bit) |

**与 Legacy API 对比**：

```c
/* 3.x Legacy (md.h HMAC) */
mbedtls_md_context_t ctx;
mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1); /* is_hmac=1 */
mbedtls_md_hmac_starts(&ctx, key, keylen);
mbedtls_md_hmac_update(&ctx, data, len);
mbedtls_md_hmac_finish(&ctx, mac);

/* 4.x PSA */
psa_key_id_t key;  /* HMAC 密钥通过 psa_import_key 导入 */
psa_mac_sign(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, len, mac, sizeof(mac), &mlen);
```

**要点**：
- HMAC 密钥需要先用 `psa_import_key()` 导入为 `PSA_KEY_TYPE_HMAC` 类型
- CMAC 直接使用 AES 密钥（`PSA_KEY_TYPE_AES`），无需额外导入
- `psa_mac_verify()` 返回 `PSA_SUCCESS` 或 `PSA_ERROR_INVALID_SIGNATURE`

→ 代码：[mbedtls_42/12_psa_mac/main.c](mbedtls_42/12_psa_mac/main.c)

---

### 示例13：PSA 非对称签名

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 功能 | 函数 |
|------|------|
| 消息签名 | `psa_sign_message(key, alg, input, inlen, sig, ssz, &slen)` |
| 消息验签 | `psa_verify_message(key, alg, input, inlen, sig, slen)` |
| 摘要签名 | `psa_sign_hash(key, alg, hash, hlen, sig, ssz, &slen)` |
| 摘要验签 | `psa_verify_hash(key, alg, hash, hlen, sig, slen)` |

**支持的算法**：

| 算法宏 | 说明 | 密钥类型 |
|--------|------|----------|
| `PSA_ALG_ECDSA(PSA_ALG_SHA_256)` | ECDSA + SHA-256 | ECC P-256/P-384 |
| `PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256)` | RSA PKCS#1 v1.5 | RSA-2048+ |
| `PSA_ALG_RSA_PSS(PSA_ALG_SHA_256)` | RSA-PSS | RSA-2048+ |

**与 Legacy API 对比**：

```c
/* 3.x Legacy (ecp.h + ecdsa.h) */
mbedtls_ecp_group grp;
mbedtls_ecdsa_context ecdsa;
mbedtls_ecp_group_init(&grp);
mbedtls_ecdsa_init(&ecdsa);
mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
mbedtls_ecp_point_read_binary(&grp, &Q, pubkey, len);
mbedtls_ecdsa_read_signature(&grp, r, s, rl, sl, hash, hlen, &Q);

/* 4.x PSA */
psa_key_id_t key;  /* ECC 密钥通过 psa_import_key/psa_generate_key 获得 */
psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hlen, sig, siglen);
```

**要点**：
- `sign_message` / `verify_message`：内部先哈希再签名（适合短消息）
- `sign_hash` / `verify_hash`：直接对已计算的摘要签名（适合大文件，避免二次哈希）
- ECC 曲线通过 `PSA_ECC_FAMILY_SECP_R1` + bits 指定，不再需要 `MBEDTLS_ECP_DP_*` 枚举
- **`psa_export_public_key()` 导出的 ECC 公钥为未压缩点格式 `0x04 || x || y`**：P-256 = **65 字节**（0x04 + 32 + 32），P-384 = **97 字节**（0x04 + 48 + 48）。缓冲区若按 64/96 字节分配会触发 `PSA_ERROR_BUFFER_TOO_SMALL`

→ 代码：[mbedtls_42/13_psa_asymmetric/main.c](mbedtls_42/13_psa_asymmetric/main.c)

---

### 示例14：PSA KDF

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 功能 | 函数 |
|------|------|
| 初始化 | `psa_key_derivation_setup(&op, alg)` |
| 输入字节 | `psa_key_derivation_input_bytes(&op, step, data, len)` |
| 输入密钥 | `psa_key_derivation_input_key(&op, step, key)` |
| 输出字节 | `psa_key_derivation_output_bytes(&op, out, len)` |
| 输出密钥 | `psa_key_derivation_output_key(&attrs, &op, &key)` |
| 中止 | `psa_key_derivation_abort(&op)` |

**支持的 KDF 算法**：

| 算法宏 | 说明 |
|--------|------|
| `PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256)` | HKDF-Extract（仅提取） |
| `PSA_ALG_HKDF(PSA_ALG_SHA_256)` | HKDF（Extract + Expand） |
| `PSA_ALG_ECDH` | ECDH 密钥协商（配合 KDF 使用） |

**HKDF 步骤标识符**（`psa_key_derivation_step_t`，定义于 `crypto_values.h`）：

| 步骤宏 | 说明 |
|--------|------|
| `PSA_KEY_DERIVATION_INPUT_SECRET` | IKM（输入密钥材料，通过密钥对象传入） |
| `PSA_KEY_DERIVATION_INPUT_SALT` | Salt（盐值） |
| `PSA_KEY_DERIVATION_INPUT_INFO` | Info（上下文信息） |

**典型用法 - HKDF-SHA256**：

```c
psa_algorithm_t alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);
psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
psa_key_derivation_setup(&op, alg);

/* IKM 必须导入为密钥对象（PSA 要求 secret 输入通过密钥传递） */
psa_key_attributes_t ikm_attrs = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_type(&ikm_attrs, PSA_KEY_TYPE_DERIVE);
psa_set_key_bits(&ikm_attrs, ikm_len * 8);
psa_set_key_usage_flags(&ikm_attrs, PSA_KEY_USAGE_DERIVE);
/* 关键：密钥策略必须允许 HKDF 算法，否则 input_key 返回 NOT_PERMITTED */
psa_set_key_algorithm(&ikm_attrs, alg);
psa_key_id_t ikm_key;
psa_import_key(&ikm_attrs, ikm, ikm_len, &ikm_key);

/* 输入顺序：SALT → SECRET → INFO */
psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, saltlen);
psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_key);
psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, infolen);

/* 输出派生密钥材料 */
uint8_t okm[32];
psa_key_derivation_output_bytes(&op, okm, 32);
psa_key_derivation_abort(&op);
psa_destroy_key(ikm_key);
```

**ECDH + HKDF 会话密钥派生**：

```c
/* ECDH 协商共享秘密：共享密钥将作为 HKDF 输入，策略必须允许 HKDF 算法 */
psa_key_attributes_t shared_attrs = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_type(&shared_attrs, PSA_KEY_TYPE_DERIVE);
psa_set_key_bits(&shared_attrs, 256);
psa_set_key_usage_flags(&shared_attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
psa_set_key_algorithm(&shared_attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256)); /* 关键 */
psa_key_id_t shared_key;
psa_key_agreement(my_private_key, peer_pubkey, publen, PSA_ALG_ECDH,
                  &shared_attrs, &shared_key);

/* 用 HKDF 从共享秘密派生会话密钥 */
psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, shared_key);
psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, infolen);
psa_key_derivation_output_key(&session_attrs, &op, &session_key);
```

**要点**：
- **作为 KDF 输入密钥（`psa_key_derivation_input_key`）的密钥，其策略必须用 `psa_set_key_algorithm()` 设置对应的 KDF 算法**（如 `PSA_ALG_HKDF(PSA_ALG_SHA_256)`），否则返回 `PSA_ERROR_NOT_PERMITTED`。这适用于 HKDF 的 IKM 密钥和 ECDH 共享秘密密钥。
- IKM 必须导入为密钥对象（`PSA_KEY_TYPE_DERIVE`），不能直接用 `input_bytes` 传 secret
- 输入顺序为 `SALT → SECRET → INFO`
- ECDH 共享秘密若需导出做一致性验证，策略需加 `PSA_KEY_USAGE_EXPORT`

→ 代码：[mbedtls_42/14_psa_kdf/main.c](mbedtls_42/14_psa_kdf/main.c)

---

### 示例15：PSA 密钥管理

**所属层次**：PSA Crypto API（`psa/crypto.h`）

**核心 API**：

| 功能 | 函数 |
|------|------|
| 生成密钥 | `psa_generate_key(&attrs, &key)` |
| 导入密钥 | `psa_import_key(&attrs, data, len, &key)` |
| 导出密钥 | `psa_export_key(key, buf, size, &len)` |
| 导出公钥 | `psa_export_public_key(key, buf, size, &len)` |
| 查询属性 | `psa_get_key_attributes(key, &attrs)` |
| 销毁密钥 | `psa_destroy_key(key)` |

**策略强制检查**：

PSA 在运行时检查密钥是否允许指定操作。如果尝试用密钥执行未授权的操作，返回 `PSA_ERROR_NOT_PERMITTED`：

```c
/* 生成只允许加密的 AES 密钥 */
psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);  /* 只有 ENCRYPT！ */
psa_generate_key(&attrs, &key);

/* 尝试解密 → PSA_ERROR_NOT_PERMITTED */
psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_PKCS7);  /* 失败! */

/* 加密 → 成功 */
psa_cipher_encrypt_setup(&op, key, PSA_ALG_CBC_PKCS7);  /* 成功 */
```

**要点**：
- **`psa_export_key()` 要求密钥策略包含 `PSA_KEY_USAGE_EXPORT`**，否则返回 `PSA_ERROR_NOT_PERMITTED`。本示例的"密钥导入/导出"演示（AES-128、ECC P-256）即在导入时设置了该标志
- 策略强制是 PSA 的核心安全特性：usage flags + algorithm 在创建/导入时确定，运行时强制检查
- 销毁密钥后，其 `key_id` 可被后续 `psa_generate_key()` 复用

**密钥 ID 空间**：
- `key_id = 0`：无效/未使用
- `key_id > 0`：有效密钥标识（由 PSA 内部分配）
- 多客户端模式下，高位编码 owner 标识

→ 代码：[mbedtls_42/15_psa_key_mgmt/main.c](mbedtls_42/15_psa_key_mgmt/main.c)

---

## 九、接口层设计：硬件驱动可替换性

> PSA Crypto 的核心价值之一是**驱动可替换性**。应用代码通过 PSA API 调用密码操作，
> 底层实现可以是纯软件（builtin）、硬件加速器、或安全元件（SE）。

### 驱动架构

```
┌─────────────────────────────────────────────────────────────┐
│  应用层 (你的代码)                                           │
│  psa_cipher_encrypt_setup(&op, key, PSA_ALG_CBC_PKCS7)     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  PSA Crypto Core (tf-psa-crypto/core/)                      │
│  - 密钥存储管理                                              │
│  - 策略检查                                                  │
│  - 操作分发                                                  │
│  - 驱动选择（根据算法+密钥类型）                               │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼───────┐   ┌──────▼──────┐   ┌───────▼───────┐
│  Builtin      │   │  Hardware   │   │  SE/HSM       │
│  (纯软件)     │   │  Accelerator│   │  Driver       │
│               │   │             │   │               │
│ aes.c         │   │ crypto_drv_ │   │ crypto_drv_   │
│ rsa.c         │   │ accelerator │   │ se            │
│ ecp.c         │   │ .c          │   │ .c            │
└───────────────┘   └─────────────┘   └───────────────┘
```

### 驱动替换机制

1. **编译期选择**：通过 `crypto_config.h` 中的 `PSA_CRYPTO_DRIVER_*` 宏选择驱动
2. **运行时分发**：PSA Core 根据算法和密钥类型，将操作路由到对应驱动
3. **透明替换**：应用代码无需修改，只需更换驱动实现

```c
/* crypto_config.h 中的驱动配置示例 */
#define PSA_CRYPTO_DRIVER_AES   /* 使用硬件 AES 加速器 */
#define PSA_CRYPTO_DRIVER_RSA   /* 使用硬件 RSA 引擎 */
#define PSA_CRYPTO_DRIVER_ECC   /* 使用 SE 处理 ECC */
/* 未定义的算法自动 fallback 到 builtin 软件实现 */
```

### 在项目中的应用

项目中的 SE（安全元件）架构天然适合 PSA 驱动模型：
- AP 侧运行 mbedTLS TLS 栈
- SE 侧通过 PSA 驱动接口提供硬件密码能力
- 密钥存储在 SE 中，不出安全边界
- `psa_key_id_t` 在 SE 中映射到硬件密钥槽位

---

---

## 十、与项目代码的对应关系

### mbedTLS 3.6 (Legacy API)

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

### mbedTLS 4.2 (PSA Crypto API)

| 教程示例 | PSA 操作 | 项目代码对应 | 说明 |
|----------|----------|-------------|------|
| 09_psa_hash | `psa_hash_compute` / streaming | TLS Finished 消息、证书指纹 | 哈希计算 |
| 10_psa_cipher | `psa_cipher_encrypt/decrypt_setup` | TLS 记录层数据加密 | AES-CBC/CTR |
| 11_psa_aead | `psa_aead_encrypt/decrypt` | TLS 1.2/1.3 记录层 | AES-GCM (首选) |
| 12_psa_mac | `psa_mac_sign/verify` | HMAC 完整性校验 | HMAC-SHA256 / CMAC |
| 13_psa_asymmetric | `psa_sign_hash/verify_hash` | CertificateVerify、证书签名 | ECDSA / RSA |
| 14_psa_kdf | `psa_key_derivation_*` | TLS 会话密钥派生 | HKDF / ECDH |
| 15_psa_key_mgmt | `psa_generate/import/export/destroy` | SE 密钥管理 | 密钥生命周期 |

---

## 十一、嵌入式集成：裁剪与交叉编译 (STM32 + FreeRTOS)

前面所有示例都在 Linux 主机上运行。本章把 mbedTLS 搬上真实嵌入式目标：

- **MCU**：STM32F407VE —— Cortex-M4F（带 FPU），168 MHz，1 MB Flash / 192 KB RAM
- **RTOS**：FreeRTOS-Kernel V11.3.0（只取内核核心 + CM4F 端口 + heap_4，不引入 CMSIS/HAL）
- **工具链**：`arm-none-eabi-gcc`（GNU Arm Embedded Toolchain）

两个示例分别对应两套 API 体系，结构完全平行：

| 示例 | API 体系 | 链接目标 | 裁剪入口 |
|------|---------|---------|---------|
| `mbedtls_36/09_embedded_stm32` | Legacy API（`aes.h` / `sha256.h` / `ecdsa.h`） | `mbedcrypto` | `MBEDTLS_USER_CONFIG_FILE` |
| `mbedtls_42/16_embedded_stm32` | PSA Crypto API（`psa/crypto.h`） | `tfpsacrypto` | `TF_PSA_CRYPTO_USER_CONFIG_FILE` |

每个固件包含三个并发任务：**SHA-256 哈希**、**AES-128-CBC 加解密往返**、**ECDSA P-256 签名/验签**，
全部通过 USART1（115200-8N1）打印结果。熵源使用 STM32F4 片上硬件 RNG（RNG 外设），
mbedTLS 内部全局状态由 FreeRTOS 互斥锁保护。

### 11.1 可替换接口总览

mbedTLS 在裸机 + RTOS 环境下需要替换三类平台接口，3.6 与 4.2 的机制不同：

| 接口 | 3.6 启用宏 | 3.6 回调签名 | 4.2 启用宏 | 4.2 回调签名 |
|------|-----------|-------------|-----------|-------------|
| **熵源** | `MBEDTLS_ENTROPY_HARDWARE_ALT` + `MBEDTLS_NO_PLATFORM_ENTROPY` | `mbedtls_hardware_poll(void *data, unsigned char *out, size_t len, size_t *olen)` | `#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY` + `#define MBEDTLS_PSA_DRIVER_GET_ENTROPY` | `mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags, size_t *estimate_bits, unsigned char *out, size_t out_size)` |
| **线程互斥锁** | `MBEDTLS_THREADING_C` + `MBEDTLS_THREADING_ALT` | `mbedtls_threading_set_alt()` —— **4 个**指针（mutex init/free/lock/unlock） | 同左 | `mbedtls_threading_set_alt()` —— **9 个**指针（新增条件变量 init/destroy/signal/broadcast/wait） |
| **标准 I/O** | newlib retarget | `_write(int fd, const char *buf, int len)` → UART | 同左 | 同左 |

要点：

1. **熵源契约（4.2）**：`mbedtls_platform_get_entropy` 必须把整个输出缓冲区填满，
   并设置 `*estimate_bits = 8 * output_size`；否则内部返回
   `PSA_ERROR_INSUFFICIENT_ENTROPY`。3.6 的 `mbedtls_hardware_poll` 则通过
   `*olen` 报告实际读到的字节数。
2. **4.2 的条件变量是"死代码"**：库内没有任何代码路径真正调用条件变量，
   9 个回调中的 5 个 cond 回调只需返回 0 的桩实现即可（见 `port/platform_glue.c`）。
3. **`set_alt` 会顺带初始化全局互斥锁**（4.2 中包括密钥槽位锁、PSA 全局数据锁、RNG 数据锁），
   因此在 `main()` 里任何 PSA 调用之前调用一次即可，无需每个任务重复设置。
4. **4.2 默认熵源在裸机上直接 `#error`**：`MBEDTLS_PSA_BUILTIN_GET_ENTROPY` 的默认实现
   只支持 Unix/Windows，非这两平台会编译报错并提示改用 `MBEDTLS_PSA_DRIVER_GET_ENTROPY`——
   这正是裸机集成的标准路径。

### 11.2 裁剪方法论：3.6 vs 4.2

两个版本都在**预处理器层面**裁剪，但粒度不同：

**3.6 —— 模块级宏（`mbedtls_user_config_stm32.h`）**

```c
/* 关掉整个模块 */
#undef MBEDTLS_RSA_C            /* RSA 全家桶 */
#undef MBEDTLS_SSL_TLS_C        /* TLS 协议栈 */
#undef MBEDTLS_X509_USE_C       /* X.509 */
#undef MBEDTLS_PSA_CRYPTO_C     /* PSA 层（本示例只用 Legacy API）*/
#undef MBEDTLS_NET_C            /* POSIX socket，裸机无法编译 */
#undef MBEDTLS_TIMING_C         /* gettimeofday，裸机无法编译 */

/* 打开 RTOS 集成所需 */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY
```

**4.2 —— `PSA_WANT_*` 算法/密钥类型级宏（`psa_user_config_stm32.h`）**

```c
/* 只保留本示例用到的算法与密钥类型，其余全部 undef */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY

/* 保留：SHA-256、AES-CBC(无填充)、ECDSA、SECP_R1_256、AES/ECC 密钥类型 */
/* 其余 PSA_WANT_ALG_* / PSA_WANT_KEY_TYPE_* / PSA_WANT_ECC_* 全部 undef */
```

关键区别：

- **3.6** 的 `mbedtls_config.h` 用 `MBEDTLS_XXX_C` 控制"模块是否存在"，
  用户配置经 `config_adjust_*.h` 做依赖修正后进入 `check_config.h` 校验。
- **4.2** 中 tf-psa-crypto 的**所有 .c 文件都会被编译**，`PSA_WANT_*` 在预处理器层面
  决定每个算法函数体是否参与编译，最终由链接器 `--gc-sections` 丢弃未引用的代码。
  因此 4.2 的裁剪粒度更细（可以只留 SHA-256 而保留整个 hash 框架），
  但必须配合 `-ffunction-sections -fdata-sections` + `--gc-sections` 才能看到体积收益。
- **两个版本都必须关掉 TLS/X.509**：`net_sockets.c`、`timing.c` 依赖 POSIX，
  裸机根本无法通过编译；且本示例不需要协议层。

### 11.3 交叉编译工具链与 CMake

**工具链文件 `arm-none-eabi.cmake`**（两个示例共用同一份）：

```cmake
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
# Cortex-M4F：单精度 FPU + 硬浮点 ABI
set(MCU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
# 每个函数/数据独立成段，配合 --gc-sections 做死代码消除
add_compile_options(${MCU_FLAGS} -ffunction-sections -fdata-sections -fno-common)
# newlib-nano + nosys：嵌入式标准库
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections --specs=nosys.specs --specs=nano.specs")
```

**CMake 结构**（以 4.2 为例，3.6 仅链接目标与裁剪变量不同）：

```cmake
# 1) 裁剪配置必须在 FetchContent_MakeAvailable 之前设置（FILEPATH 缓存变量）
set(TF_PSA_CRYPTO_USER_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/port/psa_user_config_stm32.h
    CACHE FILEPATH "" FORCE)
FetchContent_Declare(mbedtls GIT_REPOSITORY ... GIT_TAG v4.2.0
                     GIT_SUBMODULES "tf-psa-crypto" "framework")
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)   # 静态库，目标名 tfpsacrypto
# threading_alt.h 在 port/ 下，4.2 的 threading.h 会 #include 它。
# 注意：必须用目录级 include_directories()（而非 target_include_directories），
# 因为 tf-psa-crypto 内部拆成 platform/utilities/extras/core 等多个
# object library 目标，它们不继承 tfpsacrypto 的 target 级包含路径。
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/port)
FetchContent_MakeAvailable(mbedtls)

# 2) FreeRTOS：FetchContent_Populate 只取源码，手动列核心文件（不跑它的 CMake）
add_library(freertos STATIC
    .../croutine.c .../list.c .../queue.c .../stream_buffer.c
    .../tasks.c .../timers.c .../event_groups.c
    .../portable/GCC/ARM_CM4F/port.c
    .../portable/MemMang/heap_4.c)

# 3) 固件：应用 + 手写硬件层 + 平台胶水 + 启动文件
add_executable(app.elf main.c port/stm32f4_hw.c port/platform_glue.c port/startup_stm32f4.s)
target_link_libraries(app.elf PRIVATE tfpsacrypto freertos)
target_link_options(app.elf PRIVATE -T${LD_SCRIPT} -Wl,-Map=app.map
                -Wl,--gc-sections -nostartfiles)
```

**链接脚本 `stm32f407ve.ld` 的两个易错点**（本项目实际踩过的坑）：

1. 启动文件用 `ldr r2, =__etext` 定位 `.data` 的 Flash 源地址，链接脚本必须定义
   `__etext = .;`（很多模板只定义了 `_etext`）。
2. newlib-nano 的 `_sbrk`（来自 `libnosys.a`）引用符号 `end` 作为堆起点，
   链接脚本必须在 `.bss` 末尾定义 `end = .;`，否则链接报 undefined reference。

**手写硬件层 `port/stm32f4_hw.c`**（不依赖 CMSIS/HAL，直接操作寄存器）：

- `SystemInit()`：HSE 8 MHz → PLL ×336/2/2 = 168 MHz
- `hw_uart_init()` / `hw_uart_putc()`：PA9 (USART1_TX) AF7，115200-8N1，`\n` 转 `\r\n`
- `hw_rng_init()` / `hw_rng_poll()`：使能 RNG 外设（AHB1ENR bit6 + CR.RNGEN），
  轮询 SR.DRDY 读 DR —— 这就是喂给 mbedTLS 的硬件熵源

**构建加速提示**：两个示例的 `build.sh` 都支持 `MBEDTLS_SRC` 环境变量，
指向本机已有的 mbedtls 源码树（含子模块）可跳过 FetchContent 的 git clone：

```bash
# 例如复用本仓库 mbedtls_42 原生构建已拉取的源码
MBEDTLS_SRC=/path/to/mbedtls-4.2 ./build.sh
```

> 注意：`FETCHCONTENT_SOURCE_DIR_MBEDTLS` 只能作为 CMake `-D` 缓存变量传入，
> 直接设成 shell 环境变量是无效的（CMake 不会读取它）。

### 11.4 FreeRTOS 集成要点

| 要点 | 说明 |
|------|------|
| **`INCLUDE_vTaskDelete` 必须显式开启** | FreeRTOS V11 中该宏**默认值为 0**（`FreeRTOS.h`），不开则 `vTaskDelete` 不编译进内核，链接报 undefined reference。本项目三个任务结束后都调用 `vTaskDelete(NULL)` |
| **SysTick 优先级** | `configKERNEL_INTERRUPT_PRIORITY = 240`（8 位优先级最低档）。`vPortSetupTimerInterrupt` 用裸寄存器实现（SCB->SYSCLKCTRL/PENDSV/SVTIM、SHPR3），不依赖 CMSIS，把 PendSV/SysTick 压到最低，保证密码运算期间可被抢占 |
| **堆** | `heap_4.c` + `configTOTAL_HEAP_SIZE = 64 KB`；任务栈：hash/aes 各 512 字、ecc 1024 字（ECDSA 大数运算栈消耗大） |
| **互斥锁回调** | `frt_mutex_init` → `xSemaphoreCreateMutex()`，`frt_mutex_lock` → `xSemaphoreTake(pdMS_TO_TICKS(1000))`。mbedTLS 的线程锁粒度是"每次密码操作一把锁"，1 s 超时足够 |
| **断言与钩子** | `configASSERT` → `vAssertCalled()`（UART 打印后死循环）；`MallocFailedHook` / `StackOverflowHook` 打印现场 |

### 示例09：3.6 Legacy API 嵌入式固件

```
mbedtls_36/09_embedded_stm32/
├── arm-none-eabi.cmake          # 工具链文件
├── CMakeLists.txt               # mbedcrypto + FreeRTOS + app.elf
├── build.sh                     # 自动探测工具链并构建
├── main.c                       # 3 个任务：SHA-256 / AES-CBC / ECDSA P-256
├── mbedtls_user_config_stm32.h  # 3.6 裁剪配置（模块级宏）
├── result.txt                   # 构建体积 + 预期串口输出
└── port/
    ├── startup_stm32f4.s        # 向量表 + 启动代码
    ├── stm32f407ve.ld           # 链接脚本（含 __etext / end 修正）
    ├── FreeRTOSConfig.h         # RTOS 配置（含 INCLUDE_vTaskDelete=1）
    ├── stm32f4_hw.c/.h          # 手写硬件层：SystemInit / UART / RNG
    ├── threading_alt.h          # mbedtls_threading_mutex_t 定义
    └── platform_glue.c          # _write / SysTick / 熵源 / 4 个互斥锁回调
```

构建与预期输出见 `mbedtls_36/09_embedded_stm32/result.txt`。核心 API 调用：

```c
mbedtls_sha256((const unsigned char *)msg, len, hash, 0);          /* L3 哈希 */
mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plen, iv, in, out); /* L3 对称 */
mbedtls_ecdsa_genkey(&eckey, &ecgrp, f_rng, p_rng);                /* L3 ECC */
mbedtls_ecdsa_write_signature(&eckey, MBEDTLS_MD_SHA256, ...);     /* L3 签名 */
```

### 示例16：4.2 PSA API 嵌入式固件

```
mbedtls_42/16_embedded_stm32/
├── arm-none-eabi.cmake          # 工具链文件（与 3.6 相同）
├── CMakeLists.txt               # tfpsacrypto + FreeRTOS + app.elf
├── build.sh                     # 默认 STM32F407VE；./build.sh qemu → QEMU mps2-an385
├── run_qemu.sh                  # 一键 QEMU 仿真运行（mps2-an385，Cortex-M3）
├── main.c                       # 3 个任务：PSA 哈希 / PSA AES-CBC / PSA ECDSA
└── port/
    ├── startup_stm32f4.s / stm32f407ve.ld / FreeRTOSConfig.h / stm32f4_hw.c/.h
    ├── threading_alt.h          # mutex + condition_variable 两个类型
    ├── psa_user_config_stm32.h  # 4.2 裁剪配置（PSA_WANT_* 级）
    ├── platform_glue.c          # _write / SysTick / 熵源 / 9 个线程回调
    ├── startup_qemu.s           # QEMU mps2-an385 启动代码（Cortex-M3，无 FPU）
    ├── qemu_mps2.ld             # CMSDK 内存布局：RAM@0x20000000 / APB UART@0x40004000
    └── qemu_hw.c                # QEMU 硬件层：SystemInit / UART0 / RNG（熵源）
```

> **QEMU 仿真**：`./build.sh && ./run_qemu.sh`（或 `./build.sh qemu && ./run_qemu.sh`）。
> mps2-an385 板是 Cortex-M3（无硬件 FPU，25 MHz），所以 QEMU 构建切到
> FreeRTOS `GCC/ARM_CM3` 端口并禁用 FPU 相关编译选项；串口走 CMSDK APB UART0。

与 3.6 示例的 API 对照：

| 操作 | 3.6 (Legacy) | 4.2 (PSA) |
|------|-------------|-----------|
| SHA-256 | `mbedtls_sha256()` | `psa_hash_compute(PSA_ALG_SHA_256, ...)` |
| AES-CBC | `mbedtls_aes_crypt_cbc()`（IV 独立参数，会被原地修改） | 一次性接口 `psa_cipher_encrypt` **没有 IV 参数**（库内部生成随机 IV，输出 random IV‖密文）；要用固定 IV 必须走多段接口：`psa_cipher_encrypt_setup()` → `psa_cipher_set_iv(固定 IV)` → `psa_cipher_update()` + `psa_cipher_finish()`，输出就是纯密文 |
| ECDSA | `mbedtls_ecdsa_genkey/write_signature/read_signature` | `psa_generate_key()` + `psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), ...)` + `psa_verify_message()` |
| 密钥 | 结构体直接持有（`mbedtls_ecp_keypair`） | 不透明句柄 `mbedtls_svc_key_id_t`，经 `psa_import_key/psa_generate_key` 获得，用完 `psa_destroy_key` |

构建与预期输出见 `mbedtls_42/16_embedded_stm32/result.txt`（含 STM32 真机与 QEMU 两种目标）。

### 11.5 体积数据与裁剪效果

两个示例的固件体积（`arm-none-eabi-size`，MinSizeRel + `--gc-sections`）：

| 指标 | 3.6 (Legacy) | 4.2 (PSA) |
|------|-------------|-----------|
| text (Flash) | 97,092 B（≈95 KB / 1 MB，**9.5%**） | 49,760 B（≈49 KB / 1 MB，**4.8%**；QEMU Cortex-M3 目标 49,184 B） |
| data + bss (RAM) | 132 + 196,476 B（≈74 KB / 192 KB，**38%**） | 相同（同一 FreeRTOS 配置） |
| crypto 库 text | libmbedcrypto.a：171,426 B（裁剪后实际链入 ≈59 KB） | libtfpsacrypto.a：74,352 B（裁剪后实际链入 ≈43 KB） |
| FreeRTOS text | libfreertos.a：13,627 B | libfreertos.a：13,591 B（同一内核版本） |

> 注：`size` 报告的 bss=196,476 包含了链接脚本中预留到 RAM 末尾的 `._heap`
> 区域，实际静态 `.bss` 约 74 KB（见各示例 `result.txt` 中 app.map 数据）。

> RAM 占比偏高主要来自 `configTOTAL_HEAP_SIZE = 64 KB`（heap_4 静态数组计入 bss）
> 与 mbedTLS 的静态缓冲；生产环境可按任务栈实测值下调堆大小。

**裁剪效果对比**：不裁剪时 3.6 的 `mbedcrypto` 全量编译约 1 MB+ 代码，
本示例只保留 SHA-256 / AES / ECP(P-256) / ECDSA / 熵源，最终链入 Flash 不足 100 KB；
4.2 通过 `PSA_WANT_*` 把算法矩阵从"全开"裁到 3 个算法 + 3 类密钥类型，
再经 `--gc-sections` 消除框架中未引用的路径。

---

## 十二、常见问题

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
