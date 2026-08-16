/**
 * @file    threading_alt.h
 * @brief   mbedTLS 3.6 线程互斥锁的 FreeRTOS 适配层（类型定义）
 *
 * mbedTLS 在定义 MBEDTLS_THREADING_ALT 时，会 #include "threading_alt.h"，
 * 并要求该头文件定义 mbedtls_threading_mutex_t 类型。
 *
 * 设计要点：本头文件【不】包含任何 FreeRTOS 头文件，只用一个不透明指针
 * （void*）承载互斥量句柄。这样 mbedcrypto 库本身不需要知道 FreeRTOS 的
 * 存在，FreeRTOS 依赖被完全隔离在应用层的 platform_glue.c 里——这正是
 * "可替换接口"的价值：加密库与具体 RTOS 解耦。
 *
 *   - xSemaphoreCreateMutex()  → mutex_init   （platform_glue.c）
 *   - vSemaphoreDelete()       → mutex_free   （platform_glue.c）
 *   - xSemaphoreTake()         → mutex_lock   （platform_glue.c）
 *   - xSemaphoreGive()         → mutex_unlock （platform_glue.c）
 *
 * 具体回调函数实现在 platform_glue.c 中，通过 mbedtls_threading_set_alt() 注册。
 */

#ifndef THREADING_ALT_H
#define THREADING_ALT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * mbedTLS 互斥锁类型：用一个不透明指针承载 FreeRTOS 互斥量句柄。
 *
 * 注意：mbedTLS 内部会分配 mbedtls_threading_mutex_t 数组（如 key_slot_mutex），
 * 因此该类型必须是 POD（可被 calloc 零初始化）。void* 的零值即 NULL，
 * 语义正确（表示"未初始化"）。platform_glue.c 里把它当作 SemaphoreHandle_t
 * （FreeRTOS 中本身就是 void*）使用。
 */
typedef struct {
    void *handle; /* 实际是 FreeRTOS 的 SemaphoreHandle_t */
} mbedtls_threading_mutex_t;

#ifdef __cplusplus
}
#endif

#endif /* THREADING_ALT_H */
