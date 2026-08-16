/**
 * @file    mbedtls_user_config_stm32.h
 * @brief   mbedTLS 3.6 嵌入式裁剪配置（用户配置层）
 *
 * 作用机制：
 *   mbedTLS 的 build_info.h 按以下顺序包含配置：
 *     1. mbedtls/mbedtls_config.h          （默认全量配置）
 *     2. MBEDTLS_USER_CONFIG_FILE          （本文件，可 #undef / #define 覆盖）
 *     3. psa/crypto_config.h               （PSA 配置）
 *   因此本文件里 #undef 的宏会从默认配置中移除，#define 的宏会新增。
 *
 * 裁剪目标（STM32F407：1MB Flash / 192KB RAM）：
 *   本示例只用 Legacy API（SHA-256 / AES-CBC / ECDSA），不需要：
 *     - RSA（大数运算，体积大）
 *     - 整个 TLS/SSL 栈
 *     - X.509 证书解析
 *     - PSA Crypto 核心（Legacy API 可独立工作）
 *   同时启用嵌入式必需的：
 *     - 线程互斥锁（FreeRTOS 适配）
 *     - 硬件熵源（STM32F4 RNG）
 */

#ifndef MBEDTLS_USER_CONFIG_STM32_H
#define MBEDTLS_USER_CONFIG_STM32_H

/* =====================================================================
 * 一、裁剪：移除本示例用不到的模块（显著减小 Flash/RAM 占用）
 * ===================================================================== */

/* --- RSA：体积大（依赖大数），本示例不需要 --- */
#undef MBEDTLS_RSA_C

/* --- 整个 TLS/SSL 栈：config_adjust_ssl.h 会级联关闭 CLI/SRV/各协议 --- */
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C

/* --- X.509 证书（3.6 无级联，需逐个关闭）--- */
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CRT_WRITE_C

/* --- 其他不需要的模块 --- */
#undef MBEDTLS_DHM_C          /* Diffie-Hellman */
#undef MBEDTLS_PKCS12_C       /* PKCS#12 */
#undef MBEDTLS_PK_C           /* 通用密钥接口（本示例直接用 ecdsa_context）*/
#undef MBEDTLS_PK_PARSE_C     /* 依赖 PK_C，一并关闭 */
#undef MBEDTLS_PK_WRITE_C     /* 依赖 PK_C，一并关闭 */

/* --- PSA Crypto 核心：Legacy API 可独立工作，关闭以减小体积 ---
 * 注意：若改用 PSA API（psa_*），需重新打开此项。 */
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C  /* PSA 密钥存储，依赖 PSA_CRYPTO_C */
#undef MBEDTLS_LMS_C          /* LMS 签名，依赖 PSA_CRYPTO_C */

/* --- 依赖已裁剪模块的"附属开关"（check_config.h 会检查前置条件）---
 * 这些宏默认开启，但依赖 RSA / X.509 / TLS，必须显式关闭： */
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT   /* 依赖 RSA + PKCS1 */
#undef MBEDTLS_X509_CSR_PARSE_C          /* 依赖 X509_USE_C */
#undef MBEDTLS_X509_CREATE_C             /* 依赖 X509_USE_C */
#undef MBEDTLS_X509_CSR_WRITE_C          /* 依赖 X509_CREATE_C */

/* --- 时间：裸机没有 POSIX clock_gettime()，关闭时间支持 ---
 * HAVE_TIME / HAVE_TIME_DATE 默认开启，但 platform_util.c 里的
 * mbedtls_ms_time() 依赖 POSIX 时钟（裸机不存在），且只有已裁剪的
 * TLS 模块会用到它。若需要证书有效期检查等时间功能，可改用
 * MBEDTLS_PLATFORM_TIME_ALT + MBEDTLS_PLATFORM_MS_TIME_ALT 提供自定义实现。 */
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE

/* --- 计时：timing.c 只支持 Unix/Windows（gettimeofday），裸机关闭 --- */
#undef MBEDTLS_TIMING_C

/* --- 网络：net_sockets.c 依赖 POSIX socket，裸机没有（本示例也不联网）--- */
#undef MBEDTLS_NET_C
#undef MBEDTLS_PKCS7_C                   /* 依赖 X509 + RSA */
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION /* 依赖 SSL_TLS_C */

/* =====================================================================
 * 二、启用：嵌入式集成必需的"可替换接口"
 * ===================================================================== */

/* --- 线程安全：用 FreeRTOS 互斥量替代 pthread ---
 * THREADING_C  开启 mbedTLS 内部加锁
 * THREADING_ALT 使用自定义互斥锁（threading_alt.h + set_alt 回调）*/
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT

/* --- 熵源：用 STM32F4 硬件 RNG 替代 /dev/urandom ---
 * HARDWARE_ALT        启用 mbedtls_hardware_poll()（platform_glue.c 实现）
 * NO_PLATFORM_ENTROPY 关闭平台熵源（裸机没有 /dev/urandom）*/
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* =====================================================================
 * 三、保留（默认已开启，无需改动，列出以便理解依赖关系）
 * =====================================================================
 *   MBEDTLS_SHA256_C    SHA-256 哈希
 *   MBEDTLS_MD_C        消息摘要统一接口
 *   MBEDTLS_AES_C       AES 分组密码
 *   MBEDTLS_ECP_C       椭圆曲线（ECDSA 依赖）
 *   MBEDTLS_ECDSA_C     ECDSA 签名/验签
 *   MBEDTLS_BIGNUM_C    大数（ECP 依赖，默认开启）
 *   MBEDTLS_ASN1_PARSE_C / ASN1_WRITE_C   ASN.1（ECDSA 依赖，默认开启）
 *   MBEDTLS_ENTROPY_C   熵池
 *   MBEDTLS_CTR_DRBG_C  确定性随机数生成器（密钥生成用）
 *   MBEDTLS_PLATFORM_C  平台抽象层
 */

#endif /* MBEDTLS_USER_CONFIG_STM32_H */
