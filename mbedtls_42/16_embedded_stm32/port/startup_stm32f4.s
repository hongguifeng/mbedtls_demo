/**
 * @file    startup_stm32f4.s
 * @brief   STM32F407VE 启动文件（GNU AS 语法）
 *
 * 职责：
 *   1. 定义向量表（初始 SP / PC + Cortex-M 异常 + STM32F4 中断）
 *   2. Reset_Handler：拷贝 .data、清零 .bss、调用 SystemInit（弱符号）、进入 main
 *   3. 所有未使用的中断默认跳到一个死循环（可被应用代码覆盖）
 *
 * 说明：本文件不依赖 CMSIS，寄存器全部用裸地址/内联汇编访问，
 *       以便在没有完整 HAL/CMSIS 包的情况下也能交叉编译。
 */

    .syntax unified
    .cpu cortex-m4
    .fpu fpv4-sp-d16
    .thumb

/* 链接脚本提供的符号 */
    .extern Reset_Handler
    .extern g_pfnVectors
    .extern _estack
    .extern _sdata
    .extern _edata
    .extern __etext
    .extern __bss_start__
    .extern __bss_end__

    .section .isr_vector,"a",%progbits
    .type g_pfnVectors, %object
g_pfnVectors:
    .word   _estack            /*  0: 初始栈顶 */
    .word   Reset_Handler      /*  1: 复位向量 */
    .word   NMI_Handler        /*  2: NMI */
    .word   HardFault_Handler  /*  3: Hard Fault */
    .word   MemManage_Handler  /*  4: Memory Management Fault */
    .word   BusFault_Handler   /*  5: Bus Fault */
    .word   UsageFault_Handler /*  6: Usage Fault */
    .word   0                  /*  7: 保留 */
    .word   0                  /*  8: 保留 */
    .word   0                  /*  9: 保留 */
    .word   0                  /* 10: 保留 */
    .word   vPortSVCHandler    /* 11: SVCall（FreeRTOS 端口提供）*/
    .word   DebugMon_Handler   /* 12: Debug Monitor */
    .word   0                  /* 13: 保留 */
    .word   xPortPendSVHandler /* 14: PendSV（FreeRTOS 上下文切换）*/
    .word   xPortSysTickHandler/* 15: SysTick（FreeRTOS 时基）*/

    /* ---- STM32F4 IRQ 0..（节选常用，其余用 Default_Handler 兜底）---- */
    .word   WWDG_IRQHandler            /* 16  */
    .word   PVD_IRQHandler             /* 17  */
    .word   TAMP_STAMP_IRQHandler      /* 18  */
    .word   RTC_WKUP_IRQHandler        /* 19  */
    .word   FLASH_IRQHandler           /* 20  */
    .word   RCC_IRQHandler             /* 21  */
    .word   EXTI0_IRQHandler           /* 22  */
    .word   EXTI1_IRQHandler           /* 23  */
    .word   EXTI2_IRQHandler           /* 24  */
    .word   EXTI3_IRQHandler           /* 25  */
    .word   EXTI4_IRQHandler           /* 26  */
    .word   DMA1_Stream0_IRQHandler    /* 27  */
    .word   DMA1_Stream1_IRQHandler    /* 28  */
    .word   DMA1_Stream2_IRQHandler    /* 29  */
    .word   DMA1_Stream3_IRQHandler    /* 30  */
    .word   DMA1_Stream4_IRQHandler    /* 31  */
    .word   DMA1_Stream5_IRQHandler    /* 32  */
    .word   DMA1_Stream6_IRQHandler    /* 33  */
    .word   ADC_IRQHandler             /* 34  */
    .word   CAN1_TX_IRQHandler         /* 35  */
    .word   CAN1_RX0_IRQHandler        /* 36  */
    .word   CAN1_RX1_IRQHandler        /* 37  */
    .word   CAN1_SCE_IRQHandler        /* 38  */
    .word   EXTI9_5_IRQHandler         /* 39  */
    .word   TIM1_BRK_TIM9_IRQHandler   /* 40  */
    .word   TIM1_UP_TIM10_IRQHandler   /* 41  */
    .word   TIM1_TRG_COM_TIM11_IRQHandler /* 42 */
    .word   TIM1_CC_IRQHandler         /* 43  */
    .word   TIM2_IRQHandler            /* 44  */
    .word   TIM3_IRQHandler            /* 45  */
    .word   TIM4_IRQHandler            /* 46  */
    .word   I2C1_EV_IRQHandler         /* 47  */
    .word   I2C1_ER_IRQHandler         /* 48  */
    .word   I2C2_EV_IRQHandler         /* 49  */
    .word   I2C2_ER_IRQHandler         /* 50  */
    .word   SPI1_IRQHandler            /* 51  */
    .word   SPI2_IRQHandler            /* 52  */
    .word   USART1_IRQHandler          /* 53  */
    .word   USART2_IRQHandler          /* 54  */
    .word   USART3_IRQHandler          /* 55  */
    .word   EXTI15_10_IRQHandler       /* 56  */
    .word   RTC_Alarm_IRQHandler       /* 57  */
    .word   OTG_FS_WKUP_IRQHandler     /* 58  */
    .word   ETH_IRQHandler             /* 59  */
    .word   ETH_WKUP_IRQHandler        /* 60  */
    .word   CAN2_TX_IRQHandler         /* 61  */
    .word   CAN2_RX0_IRQHandler        /* 62  */
    .word   CAN2_RX1_IRQHandler        /* 63  */
    .word   CAN2_SCE_IRQHandler        /* 64  */
    .word   OTG_FS_IRQHandler          /* 65  */
    .word   DMA1_Stream7_IRQHandler    /* 66  */
    .word   USART6_IRQHandler          /* 67  */
    .word   UART7_IRQHandler           /* 68  */
    .word   UART8_IRQHandler           /* 69  */
    .word   SPI3_IRQHandler            /* 70  */
    .word   OTG_HS_EP1_IN_IRQHandler   /* 71  */
    .word   OTG_HS_EP1_OUT_IRQHandler  /* 72  */
    .word   OTG_HS_WKUP_IRQHandler     /* 73  */
    .word   OTG_HS_IRQHandler          /* 74  */
    .word   DCMI_IRQHandler            /* 75  */
    .word   0                          /* 76: CRYP (保留占位) */
    .word   HASH_RNG_IRQHandler        /* 77: HASH / RNG（硬件熵源！）*/
    .word   FPU_IRQHandler             /* 78  */

    .size g_pfnVectors, .-g_pfnVectors

    .section .text.Reset_Handler
    .weak Reset_Handler
    .type Reset_Handler, %function
Reset_Handler:
    ldr   sp, =_estack              /* 设置主栈指针 */

    /* 拷贝 .data：从 Flash(__etext) 到 RAM(__data_start__) */
    ldr   r0, =_sdata
    ldr   r1, =_edata
    ldr   r2, =__etext
bcopy:
    cmp   r0, r1
    bge   bcopy_done
    ldr   r3, [r2], #4
    str   r3, [r0], #4
    b     bcopy
bcopy_done:

    /* 清零 .bss */
    ldr   r0, =__bss_start__
    ldr   r1, =__bss_end__
    movs  r2, #0
bzero:
    cmp   r0, r1
    bge   bzero_done
    str   r2, [r0], #4
    b     bzero
bzero_done:

    bl    SystemInit                /* 弱符号，默认空实现 */
    bl    main
    bx    lr
    .size Reset_Handler, .-Reset_Handler

/* 默认中断处理：死循环（可被应用覆盖）*/
    .weak Default_Handler
    .type Default_Handler, %function
Default_Handler:
Infinite_Loop:
    b     Infinite_Loop
    .size Default_Handler, .-Default_Handler

/* 把未显式定义的中断都映射到 Default_Handler */
    .macro def_weak_handler name
    .weak \name
    .set  \name, Default_Handler
    .endm

    def_weak_handler NMI_Handler
    def_weak_handler HardFault_Handler
    def_weak_handler MemManage_Handler
    def_weak_handler BusFault_Handler
    def_weak_handler UsageFault_Handler
    /* 注意：SVCall / PendSV / SysTick 三个异常由 FreeRTOS 端口接管，
     * 向量表直接指向 vPortSVCHandler / xPortPendSVHandler / xPortSysTickHandler，
     * 因此这里不再为它们定义弱别名。*/
    def_weak_handler DebugMon_Handler
    def_weak_handler WWDG_IRQHandler
    def_weak_handler PVD_IRQHandler
    def_weak_handler TAMP_STAMP_IRQHandler
    def_weak_handler RTC_WKUP_IRQHandler
    def_weak_handler FLASH_IRQHandler
    def_weak_handler RCC_IRQHandler
    def_weak_handler EXTI0_IRQHandler
    def_weak_handler EXTI1_IRQHandler
    def_weak_handler EXTI2_IRQHandler
    def_weak_handler EXTI3_IRQHandler
    def_weak_handler EXTI4_IRQHandler
    def_weak_handler DMA1_Stream0_IRQHandler
    def_weak_handler DMA1_Stream1_IRQHandler
    def_weak_handler DMA1_Stream2_IRQHandler
    def_weak_handler DMA1_Stream3_IRQHandler
    def_weak_handler DMA1_Stream4_IRQHandler
    def_weak_handler DMA1_Stream5_IRQHandler
    def_weak_handler DMA1_Stream6_IRQHandler
    def_weak_handler ADC_IRQHandler
    def_weak_handler CAN1_TX_IRQHandler
    def_weak_handler CAN1_RX0_IRQHandler
    def_weak_handler CAN1_RX1_IRQHandler
    def_weak_handler CAN1_SCE_IRQHandler
    def_weak_handler EXTI9_5_IRQHandler
    def_weak_handler TIM1_BRK_TIM9_IRQHandler
    def_weak_handler TIM1_UP_TIM10_IRQHandler
    def_weak_handler TIM1_TRG_COM_TIM11_IRQHandler
    def_weak_handler TIM1_CC_IRQHandler
    def_weak_handler TIM2_IRQHandler
    def_weak_handler TIM3_IRQHandler
    def_weak_handler TIM4_IRQHandler
    def_weak_handler I2C1_EV_IRQHandler
    def_weak_handler I2C1_ER_IRQHandler
    def_weak_handler I2C2_EV_IRQHandler
    def_weak_handler I2C2_ER_IRQHandler
    def_weak_handler SPI1_IRQHandler
    def_weak_handler SPI2_IRQHandler
    def_weak_handler USART1_IRQHandler
    def_weak_handler USART2_IRQHandler
    def_weak_handler USART3_IRQHandler
    def_weak_handler EXTI15_10_IRQHandler
    def_weak_handler RTC_Alarm_IRQHandler
    def_weak_handler OTG_FS_WKUP_IRQHandler
    def_weak_handler ETH_IRQHandler
    def_weak_handler ETH_WKUP_IRQHandler
    def_weak_handler CAN2_TX_IRQHandler
    def_weak_handler CAN2_RX0_IRQHandler
    def_weak_handler CAN2_RX1_IRQHandler
    def_weak_handler CAN2_SCE_IRQHandler
    def_weak_handler OTG_FS_IRQHandler
    def_weak_handler DMA1_Stream7_IRQHandler
    def_weak_handler USART6_IRQHandler
    def_weak_handler UART7_IRQHandler
    def_weak_handler UART8_IRQHandler
    def_weak_handler SPI3_IRQHandler
    def_weak_handler OTG_HS_EP1_IN_IRQHandler
    def_weak_handler OTG_HS_EP1_OUT_IRQHandler
    def_weak_handler OTG_HS_WKUP_IRQHandler
    def_weak_handler OTG_HS_IRQHandler
    def_weak_handler DCMI_IRQHandler
    def_weak_handler HASH_RNG_IRQHandler
    def_weak_handler FPU_IRQHandler

    .weak SystemInit
    .type SystemInit, %function
SystemInit:
    bx lr
    .size SystemInit, .-SystemInit

    .end
