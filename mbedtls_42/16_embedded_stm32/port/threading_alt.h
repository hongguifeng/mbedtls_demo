/**
 * @file    threading_alt.h
 * @brief   mbedTLS 4.2 (TF-PSA-Crypto) 线程互斥锁 / 条件变量的裸机替代类型
 *
 * 当 MBEDTLS_THREADING_C + MBEDTLS_THREADING_ALT 开启时，
 * mbedtls/threading.h 会 #include "threading_alt.h"，并要求本头文件定义两个
 * 平台类型：
 *   - mbedtls_platform_mutex_t
 *   - mbedtls_platform_condition_variable_t
 *
 * 设计原则（与 3.6 示例一致）：
 *   1. 本头文件保持自包含，不 include FreeRTOS.h / task.h，
 *      使 tfpsacrypto 库与 RTOS 解耦（库只看到不透明指针）。
 *   2. 实际语义由 platform_glue.c 中的回调实现：
 *        - mutex  -> FreeRTOS 互斥量 (SemaphoreHandle_t)
 *        - cond   -> 本示例中库代码并不真正使用条件变量，
 *                    故用最小占位实现（见 platform_glue.c）。
 *
 * FreeRTOS 的 SemaphoreHandle_t 本质是 void*，因此这里用 void* 承载即可。
 */

#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#include <stddef.h>

/**
 * 平台互斥锁类型。
 * 实际指向一个 FreeRTOS 互斥量（SemaphoreHandle_t，即 void*）。
 * 由 platform_glue.c 的 frt_mutex_* 回调负责创建 / 加锁 / 解锁 / 销毁。
 */
typedef struct {
    void *handle;   /* SemaphoreHandle_t */
} mbedtls_platform_mutex_t;

/**
 * 平台条件变量类型。
 * TF-PSA-Crypto 4.2 的库代码本身并不调用条件变量（仅 threading.c 的包装函数
 * 引用），因此这里用一个最小占位结构即可；回调实现见 platform_glue.c。
 */
typedef struct {
    void *handle;   /* 预留：可指向 FreeRTOS 事件组 / 队列等 */
} mbedtls_platform_condition_variable_t;

#endif /* MBEDTLS_THREADING_ALT_H */
