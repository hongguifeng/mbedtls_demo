/**
 * @file    stm32f4_hw.h
 * @brief   最小硬件抽象层接口（实现见 stm32f4_hw.c）
 */

#ifndef STM32F4_HW_H
#define STM32F4_HW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 复位后时钟配置：HSE(8MHz) → PLL → SYSCLK 168MHz（由 startup 弱调用）*/
void SystemInit(void);
void SystemCoreClockUpdate(void);
extern volatile uint32_t SystemCoreClock;

/** USART1 (PA9, 115200-8N1) 初始化 */
void hw_uart_init(void);
/** 阻塞发送一个字符（'\n' 自动转 '\r\n'）*/
void hw_uart_putc(char c);

/** STM32F4 硬件 RNG 初始化 */
void hw_rng_init(void);
/** 从硬件 RNG 读取随机字节，返回实际填充字节数（0 表示无数据）*/
int hw_rng_poll(unsigned char *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* STM32F4_HW_H */
