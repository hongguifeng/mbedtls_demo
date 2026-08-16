/**
 * @file    qemu_hw.c
 * @brief   QEMU mps2-an385（Cortex-M3）硬件层 —— 与 stm32f4_hw.c 提供同一套符号
 *
 * 目标板：QEMU `-M mps2-an385`（ARM MPS2 AN385 FPGA 镜像，Cortex-M3，无 FPU）
 *   - "Flash"：SSRAM1 @ 0x00000000（4MB，armv7m_load_kernel 把 ELF 加载到这里）
 *   - RAM    ：SSRAM2&3 @ 0x20000000（4MB，本示例只用前 192KB，与 STM32F407VE 对齐）
 *   - UART   ：CMSDK APB UART @ 0x40004000（接 QEMU serial_hd(0)，即 -nographic 控制台）
 *   - 时钟   ：SYSCLK = 25 MHz（SysTick CLKSOURCE=1 时用的就是这个时钟）
 *   - RNG    ：MPS2 无硬件 RNG 外设 → 用软件 PRNG 顶替（见 hw_rng_poll 注释）
 *
 * CMSDK APB UART 寄存器（与 PL011/STM32 USART 完全不同，8N1 固定）：
 *   +0x00 DATA      写 = 发送一个字节
 *   +0x04 STATE     bit0=TXFULL（发送忙），bit1=RXFULL；只读
 *   +0x08 CTRL      bit0=TX_EN，bit1=RX_EN
 *   +0x10 BAUDDIV   波特率分频，必须 >= 16（baud = pclk / BAUDDIV）
 */

#include "stm32f4_hw.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* 时钟                                                                */
/* ------------------------------------------------------------------ */

volatile uint32_t SystemCoreClock = 25000000UL;   /* MPS2 AN385 SYSCLK = 25MHz */

void SystemCoreClockUpdate(void)
{
    SystemCoreClock = 25000000UL;
}

/* ------------------------------------------------------------------ */
/* CMSDK APB UART @ 0x40004000                                         */
/* ------------------------------------------------------------------ */

#define QEMU_UART_BASE      0x40004000UL
#define QEMU_UART_DATA      (*(volatile uint32_t *)(QEMU_UART_BASE + 0x00))
#define QEMU_UART_STATE     (*(volatile uint32_t *)(QEMU_UART_BASE + 0x04))
#define QEMU_UART_CTRL      (*(volatile uint32_t *)(QEMU_UART_BASE + 0x08))
#define QEMU_UART_BAUDDIV   (*(volatile uint32_t *)(QEMU_UART_BASE + 0x10))

#define QEMU_UART_STATE_TXFULL    (1u << 0)
#define QEMU_UART_CTRL_TX_EN      (1u << 0)

void hw_uart_init(void)
{
    /* BAUDDIV 必须 >= 16；25MHz/217 ≈ 115k，具体波特率对 QEMU 串口无意义，
     * 这里只是满足硬件约束。 */
    QEMU_UART_BAUDDIV = 217;
    QEMU_UART_CTRL |= QEMU_UART_CTRL_TX_EN;      /* 使能发送（RX 不需要）*/
}

void hw_uart_putc(char c)
{
    if (c == '\n') {
        hw_uart_putc('\r');                      /* 终端习惯：\n → \r\n */
    }
    while (QEMU_UART_STATE & QEMU_UART_STATE_TXFULL) {
        /* 等待发送 FIFO 腾空（QEMU 里几乎瞬间完成）*/
    }
    QEMU_UART_DATA = (uint32_t)(unsigned char)c;
}

/* ------------------------------------------------------------------ */
/* 熵源：软件 PRNG（演示用，非密码学安全！）                             */
/*                                                                     */
/* MPS2 AN385 没有硬件 RNG 外设。这里用一个 64-bit xorshift128+ 风格的   */
/* 伪随机数发生器顶替，保证 psa_generate_key / ECDSA nonce 有"随机"输入。*/
/* 注意：种子固定 → 每次运行生成的密钥/签名完全相同（可复现，便于验证）；  */
/*       真实产品必须使用硬件 RNG 或 TRNG，切勿照搬本实现。              */
/* ------------------------------------------------------------------ */

static uint64_t prng_state[2] = { 0x853C49E6748FEA9BULL,
                                  0xDA3E39CB94B95BDBULL };

static uint64_t prng_next(void)
{
    uint64_t x = prng_state[0];
    const uint64_t y = prng_state[1];
    prng_state[0] = y;
    x ^= x << 23;
    return prng_state[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
}

void hw_rng_init(void)
{
    /* 种子在编译期固定：保证 QEMU 下每次运行结果可复现 */
    prng_state[0] = 0x853C49E6748FEA9BULL;
    prng_state[1] = 0xDA3E39CB94B95BDBULL;
}

int hw_rng_poll(unsigned char *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = (unsigned char)prng_next();     /* 每次取低 8 位 */
    }
    return (int)len;
}
