/**
 * @file    stm32f4_hw.c
 * @brief   最小硬件抽象层（不依赖 CMSIS/HAL，裸寄存器实现）
 *
 * 提供：
 *   - SystemInit()          复位后时钟配置（HSE 8MHz → PLL → 168MHz）
 *   - hw_uart_init/putc     USART1 115200-8N1，用于打印日志
 *   - hw_rng_poll()         读取 STM32F4 硬件 RNG（RNG_DR），作为 mbedTLS 熵源
 *
 * 说明：
 *   真实项目中这些通常由 STM32CubeMX 生成。这里手写最小实现，
 *   目的是让示例可以独立交叉编译，同时展示“硬件如何接入 mbedTLS”。
 */

#include <stdint.h>
#include <stddef.h>

/* ===================== 寄存器定义（STM32F407）===================== */

#define PERIPH_BASE           ((uint32_t)0x40000000UL)
#define APB1PERIPH_BASE       PERIPH_BASE
#define APB2PERIPH_BASE       (PERIPH_BASE + 0x00010000UL)
#define AHB1PERIPH_BASE       (PERIPH_BASE + 0x00020000UL)

#define RCC_BASE              (AHB1PERIPH_BASE + 0x3800UL)
#define USART1_BASE           (APB2PERIPH_BASE + 0x3800UL)
#define RNG_BASE              (AHB1PERIPH_BASE + 0x60C000UL)

typedef struct {
    volatile uint32_t CR;        /* 0x00 */
    volatile uint32_t PLLCFGR;   /* 0x04: 主 PLL 配置（M/N/P/Q + 源选择）*/
    volatile uint32_t CFGR;      /* 0x08: 时钟切换 + AHB/APB 分频 */
    volatile uint32_t CIR;       /* 0x0C */
    volatile uint32_t AHB1RSTR;  /* 0x10 */
    volatile uint32_t AHB2RSTR;  /* 0x14 */
    volatile uint32_t AHB3RSTR;  /* 0x18 */
    volatile uint32_t APB1RSTR;  /* 0x1C */
    volatile uint32_t APB2RSTR;  /* 0x20 */
    volatile uint32_t RESERVED0; /* 0x24 */
    volatile uint32_t AHB1ENR;   /* 0x28 */
    volatile uint32_t AHB2ENR;   /* 0x2C */
    volatile uint32_t AHB3ENR;   /* 0x30 */
    volatile uint32_t APB1ENR;   /* 0x34 */
    volatile uint32_t APB2ENR;   /* 0x38 */
} RCC_TypeDef;

typedef struct {
    volatile uint32_t SR;        /* 0x00 */
    volatile uint32_t DR;        /* 0x04 */
    volatile uint32_t BRR;       /* 0x08 */
    volatile uint32_t CR1;       /* 0x0C */
    volatile uint32_t CR2;       /* 0x10 */
    volatile uint32_t CR3;       /* 0x14 */
    volatile uint32_t GTPR;      /* 0x18 */
} USART_TypeDef;

typedef struct {
    volatile uint32_t MODER;     /* 0x00 */
    volatile uint32_t OTYPER;    /* 0x04 */
    volatile uint32_t OSPEEDR;   /* 0x08 */
    volatile uint32_t PUPDR;     /* 0x0C */
    volatile uint32_t IDR;       /* 0x10 */
    volatile uint32_t ODR;       /* 0x14 */
    volatile uint32_t BSRR;      /* 0x18 */
    volatile uint32_t LCKR;      /* 0x1C */
    volatile uint32_t AFR[2];    /* 0x20, 0x24 */
} GPIO_TypeDef;

#define GPIOA_BASE          (AHB1PERIPH_BASE + 0x0000UL)

typedef struct {
    volatile uint32_t CR;        /* 0x00 */
    volatile uint32_t SR;        /* 0x04 */
    volatile uint32_t DR;        /* 0x08 */
} RNG_TypeDef;

#define RCC   ((RCC_TypeDef *)RCC_BASE)
#define USART1 ((USART_TypeDef *)USART1_BASE)
#define RNG   ((RNG_TypeDef *)RNG_BASE)
#define GPIOA ((GPIO_TypeDef *)GPIOA_BASE)

/* RCC 位定义 */
#define RCC_CR_HSEON        (1UL << 16)
#define RCC_CR_HSERDY       (1UL << 17)
#define RCC_CR_PLLON        (1UL << 24)
#define RCC_CR_PLLRDY       (1UL << 25)
#define RCC_CFGR_SW_MASK    (0x3UL)
#define RCC_CFGR_SW_PLL     (0x3UL)
#define RCC_CFGR_SWS_MASK   (0xCUL << 2)
#define RCC_CFGR_SWS_PLL    (0x8UL << 2)
#define RCC_CFGR_HPRE_MASK  (0xFUL << 4)
#define RCC_CFGR_HPRE_DIV1  (0x0UL << 4)
#define RCC_CFGR_PPRE1_MASK (0x7UL << 10)
#define RCC_CFGR_PPRE1_DIV4 (0x5UL << 10)   /* APB1 = 42MHz */
#define RCC_CFGR_PPRE2_MASK (0x7UL << 13)
#define RCC_CFGR_PPRE2_DIV2 (0x4UL << 13)   /* APB2 = 84MHz */
/* PLL 配置（HSE=8MHz → 168MHz）：
 *   PLLM=8, PLLN=336, PLLP=/2(编码0), PLLQ=7, PLLSRC=HSE(bit22=0)
 *   VCO = 8/8*336 = 336MHz, SYSCLK = 336/2 = 168MHz
 *   PLLCFGR 位域：PLLM[7:0] | PLLN[14:8] | PLLP[20:16] | PLLQ[23:21] | PLLSRC(bit22)
 *           = 0x08 | (336<<8) | (0<<16) | (7<<21) = 0x00E15008
 *   （与 STM32CubeMX 生成的 RCC->PLLCFGR = 0x00E15008 一致）*/
#define RCC_PLLCFGR_VAL     (0x00E15008UL)

/* USART 位定义 */
#define USART_CR1_UE        (1UL << 13)
#define USART_CR1_TE        (1UL << 3)
#define USART_CR1_RE        (1UL << 2)
#define USART_SR_TXE        (1UL << 7)

/* RNG 位定义 */
#define RNG_CR_RNGIE        (1UL << 2)
#define RNG_CR_RNGIE_MASK   (1UL << 2)
#define RNG_CR_DRDY         (1UL << 3)
#define RNG_CR_RNGEN        (1UL << 0)

/* ===================== 时钟配置 ===================== */

/* 前向声明（SystemInit 内部会调用）*/
void SystemCoreClockUpdate(void);

/**
 * SystemInit：HSE(8MHz) → PLL(M=8,N=336,P=2) → SYSCLK 168MHz
 * AHB=168, APB1=42, APB2=84（STM32F407 标准配置）
 */
void SystemInit(void)
{
    /* 1. 使能 HSE 并等待就绪 */
    RCC->CR |= RCC_CR_HSEON;
    while ((RCC->CR & RCC_CR_HSERDY) == 0) { }

    /* 2. 配置 AHB/APB 分频（此时仍运行在 HSE 上）*/
    RCC->CFGR &= ~(RCC_CFGR_HPRE_MASK | RCC_CFGR_PPRE1_MASK | RCC_CFGR_PPRE2_MASK);
    RCC->CFGR |= (RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV4 | RCC_CFGR_PPRE2_DIV2);

    /* 3. 配置 PLL：先清掉 PLLM/N/P/Q/SRC 字段（bit[23:0]），再写入目标值 */
    RCC->PLLCFGR &= ~0x00FFFFFFUL;
    RCC->PLLCFGR |= RCC_PLLCFGR_VAL;

    /* 4. 使能 PLL 并等待就绪 */
    RCC->CR |= RCC_CR_PLLON;
    while ((RCC->CR & RCC_CR_PLLRDY) == 0) { }

    /* 5. 切换系统时钟到 PLL */
    RCC->CFGR &= ~RCC_CFGR_SW_MASK;
    RCC->CFGR |= RCC_CFGR_SW_PLL;
    while ((RCC->CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) { }

    /* 6. 更新 SystemCoreClock（供 FreeRTOS SysTick 使用）*/
    SystemCoreClockUpdate();
}

/* ===================== 核心时钟变量 ===================== */

volatile uint32_t SystemCoreClock = 168000000UL;

void SystemCoreClockUpdate(void)
{
    /* 简化：固定 168MHz（与 SystemInit 配置一致）*/
    SystemCoreClock = 168000000UL;
}

/* ===================== USART1 (PA9, 115200-8N1) ===================== */

/**
 * 初始化 USART1：APB2=84MHz，波特率 115200 → BRR = 84e6/115200 ≈ 729.17 = 0x2D0.2C
 */
void hw_uart_init(void)
{
    /* 使能 GPIOA（PA9）和 USART1 时钟 */
    RCC->AHB1ENR |= (1UL << 0);   /* IOPAEN */
    RCC->APB2ENR |= (1UL << 14);  /* USART1EN = bit14 of APB2ENR */

    /* PA9 复用推挽，AF7（USART1_TX）*/
    GPIOA->MODER &= ~(3UL << (9 * 2));
    GPIOA->MODER |=  (2UL << (9 * 2));   /* AF mode */
    GPIOA->OSPEEDR |= (2UL << 9);        /* 中速 */
    GPIOA->AFR[1] &= ~(0xFUL << ((9 - 8) * 4));
    GPIOA->AFR[1] |=  (7UL << ((9 - 8) * 4));   /* AF7 = USART1_TX */

    /* USART1 BRR = fck / baud = 84000000 / 115200 ≈ 729.17
     * BRR = (mant << 4) | frac; mant=729=0x2D1, frac≈3 → 0x2D13（误差 <0.1%）*/
    USART1->BRR = 0x2D13;

    /* 使能接收/发送/USART */
    USART1->CR1 = USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
}

/** 阻塞发送一个字符（教学用；生产环境建议 DMA + 环形缓冲）*/
void hw_uart_putc(char c)
{
    if (c != '\n') {
        while ((USART1->SR & USART_SR_TXE) == 0) { }
        USART1->DR = (uint32_t)(uint8_t)c;
    } else {
        while ((USART1->SR & USART_SR_TXE) == 0) { }
        USART1->DR = (uint32_t)'\r';
        while ((USART1->SR & USART_SR_TXE) == 0) { }
        USART1->DR = (uint32_t)'\n';
    }
}

/* ===================== 硬件 RNG（mbedTLS 熵源）===================== */

/**
 * 初始化 STM32F4 硬件随机数发生器
 */
void hw_rng_init(void)
{
    RCC->AHB1ENR |= (1UL << 6);   /* RNGEN */
    RNG->CR |= RNG_CR_RNGEN;      /* 使能 RNG */
}

/**
 * 从硬件 RNG 读取随机字节。
 * 返回实际填充的字节数（0 表示当前无可用数据）。
 * 该函数将被 mbedTLS 作为熵源回调调用（见 platform_glue.c）。
 */
int hw_rng_poll(unsigned char *out, size_t len)
{
    size_t i = 0;
    for (i = 0; i < len; i++) {
        /* 等待 DRDY（带超时，防止硬件故障时死等）*/
        uint32_t timeout = 100000UL;
        while ((RNG->SR & RNG_CR_DRDY) == 0) {
            if (--timeout == 0) {
                break;
            }
        }
        if ((RNG->SR & RNG_CR_DRDY) == 0) {
            break;
        }
        out[i] = (unsigned char)(RNG->DR & 0xFFUL);
    }
    return (int)i;
}
