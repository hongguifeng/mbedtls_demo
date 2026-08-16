/**
 * @file    psa_user_config_stm32.h
 * @brief   mbedTLS 4.2 (TF-PSA-Crypto) 嵌入式裁剪配置（STM32F407 + FreeRTOS）
 *
 * 通过 CMake 变量 TF_PSA_CRYPTO_USER_CONFIG_FILE 注入，
 * 在 tf-psa-crypto/include/psa/crypto_config.h 之后被包含，
 * 因此可以用 #define / #undef 覆盖默认值。
 *
 * 裁剪目标：只保留本示例用到的算法
 *   - SHA-256            （psa_hash_compute）
 *   - AES-128-CBC        （psa_cipher_encrypt / decrypt，PSA_ALG_CBC_NO_PADDING）
 *   - ECDSA P-256        （psa_generate_key + psa_sign_message / verify）
 * 其余全部关闭。
 */

#ifndef PSA_USER_CONFIG_STM32_H
#define PSA_USER_CONFIG_STM32_H

/* =====================================================================
 * 1. 线程安全：用 FreeRTOS 互斥锁替代 pthread
 *    （threading_alt.h 定义平台类型，platform_glue.c 提供回调）
 * ===================================================================== */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT

/* =====================================================================
 * 2. 熵源：裸机没有 /dev/urandom、getrandom()。
 *    默认 MBEDTLS_PSA_BUILTIN_GET_ENTROPY 在非 Unix/Windows 平台会直接 #error，
 *    必须关闭它并改用驱动式熵源接口 mbedtls_platform_get_entropy()，
 *    由 platform_glue.c 实现（读取 STM32F4 硬件 RNG）。
 * ===================================================================== */
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY

/* =====================================================================
 * 3. 算法裁剪：关闭默认开启、但本示例用不到的 PSA_WANT_*
 *    （crypto_config.h 中它们全部默认为 1）
 * ===================================================================== */

/* --- 对称加密：只留 AES-CBC，关掉其余模式与算法 --- */
#undef PSA_WANT_ALG_CBC_PKCS7          /* 只用 CBC_NO_PADDING（默认开）*/
#undef PSA_WANT_ALG_CCM
#undef PSA_WANT_ALG_CCM_STAR_NO_TAG
#undef PSA_WANT_ALG_CMAC
#undef PSA_WANT_ALG_CFB
#undef PSA_WANT_ALG_CHACHA20_POLY1305
#undef PSA_WANT_ALG_CTR
#undef PSA_WANT_ALG_ECB_NO_PADDING
#undef PSA_WANT_ALG_GCM
#undef PSA_WANT_ALG_OFB
#undef PSA_WANT_ALG_STREAM_CIPHER

/* --- 非对称：只留 ECDSA，关掉 RSA / FFDH / ECDH / JPAKE --- */
#undef PSA_WANT_ALG_DETERMINISTIC_ECDSA
#undef PSA_WANT_ALG_ECDH
#undef PSA_WANT_ALG_FFDH
#undef PSA_WANT_ALG_JPAKE
#undef PSA_WANT_ALG_RSA_OAEP
#undef PSA_WANT_ALG_RSA_PKCS1V15_CRYPT
#undef PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#undef PSA_WANT_ALG_RSA_PSS

/* --- 哈希：只留 SHA-256 --- */
#undef PSA_WANT_ALG_SHA_1
#undef PSA_WANT_ALG_SHA_224
#undef PSA_WANT_ALG_SHA_384
#undef PSA_WANT_ALG_SHA_512
#undef PSA_WANT_ALG_SHA3_224
#undef PSA_WANT_ALG_SHA3_256
#undef PSA_WANT_ALG_SHA3_384
#undef PSA_WANT_ALG_SHA3_512
#undef PSA_WANT_ALG_SHAKE128
#undef PSA_WANT_ALG_SHAKE256
#undef PSA_WANT_ALG_MD5
#undef PSA_WANT_ALG_RIPEMD160

/* --- KDF / MAC：全部用不到 --- */
#undef PSA_WANT_ALG_HMAC
#undef PSA_WANT_ALG_HKDF
#undef PSA_WANT_ALG_HKDF_EXTRACT
#undef PSA_WANT_ALG_HKDF_EXPAND
#undef PSA_WANT_ALG_PBKDF2_HMAC
#undef PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
#undef PSA_WANT_ALG_TLS12_PRF
#undef PSA_WANT_ALG_TLS12_PSK_TO_MS
#undef PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS

/* --- 曲线：只留 P-256（ECDSA 需要）--- */
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_256
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_384
#undef PSA_WANT_ECC_BRAINPOOL_P_R1_512
#undef PSA_WANT_ECC_MONTGOMERY_255
#undef PSA_WANT_ECC_MONTGOMERY_448
#undef PSA_WANT_ECC_SECP_K1_256
#undef PSA_WANT_ECC_SECP_R1_384
#undef PSA_WANT_ECC_SECP_R1_521

/* --- DH 参数：用不到 --- */
#undef PSA_WANT_DH_RFC7919_2048
#undef PSA_WANT_DH_RFC7919_3072
#undef PSA_WANT_DH_RFC7919_4096
#undef PSA_WANT_DH_RFC7919_6144
#undef PSA_WANT_DH_RFC7919_8192

/* --- 密钥类型：关掉 RSA / DH / 派生 / 口令 / 其它对称算法 --- */
#undef PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
#undef PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
#undef PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY
#undef PSA_WANT_KEY_TYPE_DERIVE
#undef PSA_WANT_KEY_TYPE_PASSWORD
#undef PSA_WANT_KEY_TYPE_PASSWORD_HASH
#undef PSA_WANT_KEY_TYPE_HMAC
#undef PSA_WANT_KEY_TYPE_ARIA
#undef PSA_WANT_KEY_TYPE_CAMELLIA
#undef PSA_WANT_KEY_TYPE_CHACHA20

/* =====================================================================
 * 4. 时间：裸机没有 clock_gettime()。
 *    4.2 的 platform_util.c 在 MBEDTLS_HAVE_TIME 开启且非 Unix/Windows
 *    时会 #error "No mbedtls_ms_time available"，
 *    因此用 MBEDTLS_PLATFORM_MS_TIME_ALT 提供自定义实现
 *    （platform_glue.c 中基于 FreeRTOS tick，1ms/tick）。
 * ===================================================================== */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* 本示例不解析证书，不需要日期/时间（gmtime 等）*/
#undef MBEDTLS_HAVE_TIME_DATE

/* =====================================================================
 * 5. 其它平台相关裁剪
 * ===================================================================== */
/* 裸机没有文件系统，关掉 PEM/DER 文件读写辅助（本示例不解析证书）*/
#undef MBEDTLS_FS_IO

/* PSA 密钥持久化存储依赖文件系统（check_config.h 强制要求 FS_IO）。
 * 本示例的密钥全部在 RAM 中生成、用完即毁，不需要掉电保存，
 * 因此一并关掉存储层。 */
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C

#endif /* PSA_USER_CONFIG_STM32_H */
