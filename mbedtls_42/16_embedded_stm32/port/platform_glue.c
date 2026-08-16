/**
 * @file    platform_glue.c
 * @brief   mbedTLS 4.2 + STM32F407 + FreeRTOS 平台适配层
 *
 * 职责：
 *   1. newlib 重定向：printf -> USART1（_write）
 *   2. SysTick 配置：vPortSetupTimerInterrupt（FreeRTOS 1ms tick）
 *   3. mbedTLS 4.2 熵源驱动：mbedtls_platform_get_entropy()
 *      （MBEDTLS_PSA_DRIVER_GET_ENTROPY，读取 STM32F4 硬件 RNG）
 *   3b. mbedTLS 4.2 毫秒时基：mbedtls_ms_time()
 *       （MBEDTLS_PLATFORM_MS_TIME_ALT，基于 FreeRTOS tick）
 *   4. mbedTLS 4.2 线程适配：mbedtls_threading_set_alt()
 *      （9 个回调：4 个互斥锁 + 5 个条件变量，基于 FreeRTOS）
 *   5. FreeRTOS 钩子：断言 / malloc 失败 / 栈溢出
 */

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "psa/crypto.h"
#include "mbedtls/threading.h"
#include "mbedtls/platform.h"

#include "stm32f4_hw.h"

/* =====================================================================
 * 1. newlib 重定向：printf -> 串口（带控制台串行化）
 *
 * 三个任务并发 printf，若无保护会输出交错。这里用一把 FreeRTOS 互斥锁
 * 串行化控制台访问：
 *   - _write() 每次调用（= 一行/一段 printf 的内容）持锁；
 *   - main.c 里每个任务整体再持锁一次（mbedtls_console_lock/unlock），
 *     使同一任务的输出作为一个连续块出现。
 * 持锁者是当前任务时 _write 直接复用（可重入），不会死锁。
 * ===================================================================== */

static SemaphoreHandle_t console_mux   = NULL;
static TaskHandle_t      console_owner = NULL;

void mbedtls_console_lock_setup(void)
{
    if (console_mux == NULL) {
        console_mux = xSemaphoreCreateMutex();
    }
}

/* 获取控制台锁。返回 1 = 本次调用新拿到了锁；
 * 返回 0 = 无需锁（中断上下文/锁未建）或当前任务已持有（可重入）。 */
static int console_acquire(void)
{
    /* 中断上下文中不能拿互斥锁，直接输出；调度器未启动时
     * （main 里的横幅）xSemaphoreTake 会短暂阻塞到调度器启动，无害 */
    if (console_mux == NULL || xPortIsInsideInterrupt()) {
        return 0;
    }
    TaskHandle_t self = xTaskGetCurrentTaskHandle();
    if (console_owner == self) {
        return 0;                     /* 本任务已持有（任务级锁内再 printf）*/
    }
    xSemaphoreTake(console_mux, portMAX_DELAY);
    console_owner = self;
    return 1;
}

static void console_release(int took)
{
    if (!took) {
        return;
    }
    console_owner = NULL;
    if (xSemaphoreGive(console_mux)) {
        portYIELD();                  /* 唤醒了更高等级等待者，主动让出 */
    }
}

/* 任务级控制台锁：包住整个任务输出段（见 main.c 各 task）*/
void mbedtls_console_lock(void)
{
    (void)console_acquire();
}

void mbedtls_console_unlock(void)
{
    console_release(1);               /* 与 lock() 严格配对使用 */
}

int _write(int fd, const char *buf, int len)
{
    (void)fd;
    int took = console_acquire();
    for (int i = 0; i < len; i++) {
        hw_uart_putc(buf[i]);
    }
    console_release(took);            /* 只释放本次调用新拿到的锁 */
    return len;
}

/* =====================================================================
 * 2. SysTick：FreeRTOS 1ms tick（覆盖 port.c 中的弱定义）
 * ===================================================================== */
void vPortSetupTimerInterrupt(void)
{
    volatile uint32_t *systick_ctrl = (volatile uint32_t *)0xE000E010;
    volatile uint32_t *systick_load = (volatile uint32_t *)0xE000E014;
    volatile uint32_t *systick_val  = (volatile uint32_t *)0xE000E018;
    volatile uint32_t *shpr3        = (volatile uint32_t *)0xE000ED20;

    /* 停止并清零 SysTick */
    *systick_ctrl = 0UL;
    *systick_val  = 0UL;

    /* 配置 SysTick 以 configTICK_RATE_HZ 频率中断 */
    *systick_load = (configSYSTICK_CLOCK_HZ / configTICK_RATE_HZ) - 1UL;

    /* 关键：设置 SysTick 优先级 = configKERNEL_INTERRUPT_PRIORITY（最低）。
     * SHPR3 的 bit[31:24] 对应 SysTick 中断优先级。*/
    *shpr3 = (*shpr3 & 0x00FFFFFFUL) |
             ((uint32_t)configKERNEL_INTERRUPT_PRIORITY << 24);

    /* 使能：时钟源(bit2) + 中断(bit1) + 使能(bit0) */
    *systick_ctrl = (1UL << 2) | (1UL << 1) | (1UL << 0);
}

/* =====================================================================
 * 3. mbedTLS 4.2 熵源驱动
 *
 * 契约（见 tf-psa-crypto/drivers/builtin/src/entropy_poll.c）：
 *   - 用真随机数填满 output[0..output_size)
 *   - 设置 *estimate_bits = 8 * output_size（表示整段都是满熵）
 *   - 返回 0；失败返回非 0（调用方会报 MBEDTLS_ERR_ENTROPY_SOURCE_FAILED）
 * ===================================================================== */
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                 size_t *estimate_bits,
                                 unsigned char *output, size_t output_size)
{
    (void)flags;   /* 目前库只传 PSA_DRIVER_GET_ENTROPY_FLAGS_NONE */

    int got = hw_rng_poll(output, output_size);
    if (got <= 0 || (size_t)got < output_size) {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

    *estimate_bits = 8 * output_size;
    return 0;
}

/* =====================================================================
 * 3b. 毫秒时基：MBEDTLS_PLATFORM_MS_TIME_ALT
 *
 * 4.2 的 platform_util.c 在 MBEDTLS_HAVE_TIME 开启且非 Unix/Windows
 * 平台时要求提供 mbedtls_ms_time()（否则 #error）。
 * 这里用 FreeRTOS tick 实现：configTICK_RATE_HZ = 1000，即 1 tick = 1 ms。
 * 注意：调度器启动前调用时返回 0，对本示例无影响。
 * ===================================================================== */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

/* =====================================================================
 * 4. mbedTLS 4.2 线程适配（FreeRTOS 互斥锁 + 条件变量）
 *
 * 4.2 的 mbedtls_threading_set_alt() 需要 9 个回调：
 *   mutex_init / mutex_destroy / mutex_lock / mutex_unlock
 *   cond_init  / cond_destroy  / cond_signal / cond_broadcast / cond_wait
 *
 * 互斥锁：FreeRTOS 递归无关的普通互斥量（xSemaphoreCreateMutex）。
 * 条件变量：TF-PSA-Crypto 4.2 的库代码并不真正使用条件变量
 *           （仅 threading.c 的包装函数引用），这里给出最小实现：
 *           cond_wait 直接返回成功（不阻塞），signal/broadcast 空操作。
 *           若未来库开始使用条件变量，应改用 FreeRTOS 事件组实现。
 * ===================================================================== */

/* ---------- 互斥锁回调 ---------- */

static int frt_mutex_init(mbedtls_platform_mutex_t *mutex)
{
    mutex->handle = xSemaphoreCreateMutex();
    return (mutex->handle != NULL) ? 0 : PSA_ERROR_INSUFFICIENT_MEMORY;
}

static void frt_mutex_destroy(mbedtls_platform_mutex_t *mutex)
{
    if (mutex->handle != NULL) {
        vSemaphoreDelete((SemaphoreHandle_t)mutex->handle);
        mutex->handle = NULL;
    }
}

static int frt_mutex_lock(mbedtls_platform_mutex_t *mutex)
{
    if (xSemaphoreTake((SemaphoreHandle_t)mutex->handle,
                       pdMS_TO_TICKS(1000)) != pdTRUE) {
        return PSA_ERROR_GENERIC_ERROR;   /* 超时：视为使用错误 */
    }
    return 0;
}

static int frt_mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
    if (xSemaphoreGive((SemaphoreHandle_t)mutex->handle) != pdTRUE) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return 0;
}

/* ---------- 条件变量回调（最小实现，见上方说明）---------- */

static int frt_cond_init(mbedtls_platform_condition_variable_t *cond)
{
    cond->handle = NULL;
    return 0;
}

static void frt_cond_destroy(mbedtls_platform_condition_variable_t *cond)
{
    cond->handle = NULL;
}

static int frt_cond_signal(mbedtls_platform_condition_variable_t *cond)
{
    (void)cond;
    return 0;
}

static int frt_cond_broadcast(mbedtls_platform_condition_variable_t *cond)
{
    (void)cond;
    return 0;
}

static int frt_cond_wait(mbedtls_platform_condition_variable_t *cond,
                         mbedtls_platform_mutex_t *mutex)
{
    /* 库当前不使用条件变量；若被调用，直接返回成功（不阻塞）。
     * 注意：按 POSIX 语义 cond_wait 应先释放 mutex 再等待，
     * 这里为保持最小实现不做该动作。 */
    (void)cond;
    (void)mutex;
    return 0;
}

/* ---------- 注册入口（main 中、任何 mbedTLS 调用之前执行一次）---------- */

void mbedtls_platform_setup_threading(void)
{
    mbedtls_threading_set_alt(
        frt_mutex_init,
        frt_mutex_destroy,
        frt_mutex_lock,
        frt_mutex_unlock,
        frt_cond_init,
        frt_cond_destroy,
        frt_cond_signal,
        frt_cond_broadcast,
        frt_cond_wait);
}

/* =====================================================================
 * 5. FreeRTOS 钩子
 * ===================================================================== */

void vAssertCalled(unsigned long line, const char *file)
{
    printf("[ASSERT] %s:%lu\r\n", file, (unsigned)line);
    for (;;) {
    }
}

void vApplicationMallocFailedHook(void)
{
    printf("[FATAL] FreeRTOS heap exhausted\r\n");
    for (;;) {
    }
}

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    printf("[FATAL] stack overflow in task: %s\r\n", pcTaskName);
    for (;;) {
    }
}
