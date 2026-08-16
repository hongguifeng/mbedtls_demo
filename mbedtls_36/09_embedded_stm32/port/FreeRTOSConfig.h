/*
 * FreeRTOSConfig.h —— STM32F407 + ARM_CM4F 端口配置
 *
 * 关键点：
 *   - configCPU_CLOCK_HZ 必须等于 SystemCoreClock（168 MHz），SysTick 时基依赖它
 *   - configMAX_SYSCALL_INTERRUPT_PRIORITY 决定哪些中断优先级可以调用 FreeRTOS API
 *     （数值越大优先级越低；ARM_CM4F 端口要求 PendSV/SysTick 使用最低优先级）
 *   - 使用 heap_4（可合并碎片的动态堆），configTOTAL_HEAP_SIZE 即 FreeRTOS 堆大小
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* ---------- 时钟与处理器 ---------- */
#define configCPU_CLOCK_HZ                ((unsigned long)168000000UL)
/* SysTick 时基 = CPU 时钟（Cortex-M4 SysTick 默认用内核时钟）*/
#define configSYSTICK_CLOCK_HZ            (configCPU_CLOCK_HZ)
/* 系统节拍频率：1000 Hz（1ms/tick）*/
#define configTICK_RATE_HZ                ((TickType_t)1000)
#define configUSE_PREEMPTION              1
#define configUSE_IDLE_HOOK               0
#define configUSE_TICK_HOOK               0
#define configMAX_PRIORITIES              (5)
#define configMINIMAL_STACK_SIZE          ((unsigned short)128)
#define configTOTAL_HEAP_SIZE             ((size_t)(64 * 1024))   /* FreeRTOS 堆 64KB */
#define configMAX_TASK_NAME_LEN           (16)
#define configUSE_16_BIT_TICKS            0
#define configIDLE_SHOULD_YIELD           1
#define configUSE_MUTEXES                 1
#define configUSE_RECURSIVE_MUTEXES       1
#define configUSE_COUNTING_SEMAPHORES     1
#define configQUEUE_REGISTRY_SIZE         8

/* ---------- 中断优先级分组 ---------- */
/* STM32F4 使用 4 位抢占优先级（0-15），0 最高。
 * FreeRTOS 要求：configMAX_SYSCALL_INTERRUPT_PRIORITY 是“可调用 API 的最高数值”。
 * 设为 5，则优先级 0..4 的中断禁止调用 FreeRTOS API，5..15 允许。 */
#define configPRIO_BITS                   4
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY          15
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY     5
#define configKERNEL_INTERRUPT_PRIORITY      (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))

/* ---------- 可选特性 ---------- */
#define configUSE_TASK_NOTIFICATIONS      1
#define configCHECK_FOR_STACK_OVERFLOW    2
#define configUSE_MALLOC_FAILED_HOOK      1
#define configUSE_APPLICATION_TASK_TAG    0
#define configDYNAMIC_ALLOCATION_AT_IDLE_TIME 1

/* FreeRTOS V11 起，任务删除/挂起等 API 默认关闭（INCLUDE_* = 0），
 * 需要显式打开才会编译进内核。本示例的演示任务跑完会自删，故开启。 */
#define INCLUDE_vTaskDelete               1

/* ---------- 断言 ---------- */
#include <stdio.h>
void vAssertCalled(unsigned long line, const char *file);
#define configASSERT(x) if (!(x)) vAssertCalled((unsigned long)__LINE__, __FILE__)

/* ---------- 可选：统计信息（调试用，默认关闭）---------- */
#define configGENERATE_RUN_TIME_STATS     0
#define configUSE_TRACE_FACILITY          0
#define configUSE_STATS_FORMATTING_FUNCTIONS 0

#endif /* FREERTOS_CONFIG_H */
