/**
 * @file    platform_glue.c
 * @brief   mbedTLS 3.6 ↔ STM32/FreeRTOS 平台适配层（"胶水代码"）
 *
 * 这是嵌入式集成 mbedTLS 的核心：把 mbedTLS 的"可替换接口"接到具体硬件/RTOS 上。
 *
 * 本文件实现 4 类适配：
 *   1. 熵源        mbedtls_hardware_poll()      → STM32F4 硬件 RNG（hw_rng_poll）
 *   2. 线程互斥锁   FreeRTOS 互斥量回调          → mbedtls_threading_set_alt()
 *   3. 标准 I/O     __write()（newlib 重定向）    → USART1（hw_uart_putc）
 *   4. 断言/钩子    vAssertCalled() / malloc 失败钩子
 *
 * 为什么需要这些？
 *   mbedTLS 默认面向 POSIX 主机：熵来自 /dev/urandom，互斥锁用 pthread，
 *   printf 走终端。裸机 + FreeRTOS 环境下这三者都不存在，必须逐一替换。
 *   mbedTLS 为此预留了"可替换接口"（见 README 第九章），本文件就是这些接口的落地。
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "mbedtls/threading.h"
#include "stm32f4_hw.h"

/* =====================================================================
 * 1. 熵源：mbedtls_hardware_poll() → STM32F4 硬件 RNG
 * =====================================================================
 * 由 MBEDTLS_ENTROPY_HARDWARE_ALT 启用。mbedTLS 的 entropy 模块会周期性调用它
 * 收集随机字节（见 library/entropy.c）。第一个参数必须接受 NULL。
 *
 * 注意：这里直接读硬件 RNG，不经过 FreeRTOS API，因此可在任意上下文调用。
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data; /* 必须接受 NULL */

    int got = hw_rng_poll(output, len);
    if (got <= 0) {
        return -1; /* 无数据，entropy 模块会重试其他源 */
    }
    if (olen != NULL) {
        *olen = (size_t)got;
    }
    return 0;
}

/* =====================================================================
 * 2. 线程互斥锁：FreeRTOS 互斥量 → mbedTLS threading alt
 * =====================================================================
 * 由 MBEDTLS_THREADING_C + MBEDTLS_THREADING_ALT 启用。
 * mbedtls_threading_mutex_t 在 threading_alt.h 中定义为 { SemaphoreHandle_t }。
 */

static void frt_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    /* 失败时置 NULL，使后续 lock 失败（符合 mbedTLS 约定）*/
    mutex->handle = xSemaphoreCreateMutex();
}

static void frt_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->handle != NULL) {
        vSemaphoreDelete(mutex->handle);
        mutex->handle = NULL;
    }
}

static int frt_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->handle == NULL) {
        return -1;
    }
    /* 带超时，避免死锁时永久阻塞（教学用 1s；生产可按需调整）*/
    if (xSemaphoreTake(mutex->handle, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return -1;
    }
    return 0;
}

static int frt_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->handle == NULL) {
        return -1;
    }
    if (xSemaphoreGive(mutex->handle) != pdTRUE) {
        return -1;
    }
    return 0;
}

/**
 * 注册 FreeRTOS 互斥量回调。必须在调用任何 mbedTLS 加密 API 之前、
 * 且在调度器启动后（xSemaphoreCreateMutex 需要调度器运行）调用一次。
 */
void mbedtls_platform_setup_threading(void)
{
    mbedtls_threading_set_alt(frt_mutex_init,
                              frt_mutex_free,
                              frt_mutex_lock,
                              frt_mutex_unlock);
}

/* =====================================================================
 * 3. 标准 I/O 重定向：printf → USART1
 * =====================================================================
 * newlib-nano 的 printf 最终调用系统调用 _write()（libc.a 中为未定义符号，
 * 必须由应用提供）。这里实现它，把 stdout/stderr 都导向 hw_uart_putc。
 * 这样 mbedTLS 内部及示例代码都可以直接用 printf 打印日志。
 */
int _write(int fd, const char *buf, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        hw_uart_putc(buf[i]);
    }
    return len;
}

/* =====================================================================
 * 5. SysTick 优先级：覆盖 FreeRTOS 弱函数 vPortSetupTimerInterrupt()
 * =====================================================================
 * FreeRTOS 的 CM4F port 提供的弱实现只配置了 SysTick 的计数与使能，
 * 但【没有】设置 SysTick 中断优先级。而 FreeRTOS 要求 tick 中断优先级
 * 必须等于 configKERNEL_INTERRUPT_PRIORITY（最低优先级），否则任务切换
 * （PendSV）无法抢占 tick，调度器会出错。
 *
 * 这里覆盖该弱函数：在配置 SysTick 的同时，通过 SHPR3 寄存器
 * （0xE000ED20 的 bit[31:24]）把 SysTick 优先级设为 configKERNEL_INTERRUPT_PRIORITY。
 */
void vPortSetupTimerInterrupt(void)
{
    /* 与 port.c 弱实现相同的 SysTick 配置 */
    volatile uint32_t *systick_ctrl = (volatile uint32_t *)0xE000E010;
    volatile uint32_t *systick_load = (volatile uint32_t *)0xE000E014;
    volatile uint32_t *systick_val  = (volatile uint32_t *)0xE000E018;
    volatile uint32_t *shpr3        = (volatile uint32_t *)0xE000ED20;

    /* 停止并清零 SysTick */
    *systick_ctrl = 0UL;
    *systick_val  = 0UL;

    /* 配置 SysTick 以 configTICK_RATE_HZ 频率中断 */
    *systick_load = (configSYSTICK_CLOCK_HZ / configTICK_RATE_HZ) - 1UL;

    /* 关键：设置 SysTick 优先级 = configKERNEL_INTERRUPT_PRIORITY（最低）
     * SHPR3 的 bit[31:24] 对应 SysTick 中断优先级。*/
    *shpr3 = (*shpr3 & 0x00FFFFFFUL) |
             ((uint32_t)configKERNEL_INTERRUPT_PRIORITY << 24);

    /* 使能：时钟源(bit2) + 中断(bit1) + 使能(bit0) */
    *systick_ctrl = (1UL << 2) | (1UL << 1) | (1UL << 0);
}

/* =====================================================================
 * 4. 断言与内存失败钩子
 * ===================================================================== */

/** FreeRTOS configASSERT 回调：打印位置后死循环（便于串口定位）*/
void vAssertCalled(unsigned long line, const char *file)
{
    printf("\r\n!!! ASSERT FAILED: %s:%lu\r\n", file, line);
    for (;;) {
        /* 死循环，等待调试器或看门狗复位 */
    }
}

/** FreeRTOS heap_4 分配失败钩子（configUSE_MALLOC_FAILED_HOOK=1）*/
void vApplicationMallocFailedHook(void)
{
    printf("\r\n!!! FreeRTOS heap allocation FAILED\r\n");
    for (;;) {
    }
}

/** 栈溢出钩子（configCHECK_FOR_STACK_OVERFLOW=2）*/
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    printf("\r\n!!! STACK OVERFLOW in task: %s\r\n", pcTaskName);
    for (;;) {
    }
}
