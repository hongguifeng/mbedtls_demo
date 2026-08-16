/**
 * @file    startup_qemu.s
 * @brief   QEMU mps2-an385（Cortex-M3）启动文件（GNU AS 语法）
 *
 * 与 startup_stm32f4.s 的区别：
 *   - .cpu cortex-m3，无 .fpu（M3 没有 FPU，soft-float）
 *   - 向量表只保留 Cortex-M 标准异常 + MPS2 的 32 个 IRQ（全部兜底到 Default_Handler）
 *   - Reset_Handler 逻辑完全一致：先设 SP，再拷 .data、清 .bss、调 SystemInit、进 main
 *
 * QEMU M-profile 复位行为（target/arm/cpu.c arm_cpu_reset）：
 *   从向量表 0x0 读初始 SP、0x4 读初始 PC。因此 .isr_vector 必须位于
 *   加载地址 0x00000000（见 qemu_mps2.ld），且本文件第一条指令仍是
 *   `ldr sp,=_estack`（双保险，也兼容直接 -kernel 加载 ELF 的场景）。
 */

    .syntax unified
    .cpu cortex-m3
    .thumb

/* 链接脚本提供的符号 */
    .extern Reset_Handler
    .extern g_pfnVectors
    .extern _estack
    .extern _sdata
    .extern _edata
    .extern _sidata
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

    /* ---- MPS2 AN385 IRQ 0..31（全部兜底到 Default_Handler）---- */
    .rept 32
    .word   Default_Handler
    .endr

    .size g_pfnVectors, .-g_pfnVectors

    .section .text.Reset_Handler
    .weak Reset_Handler
    .type Reset_Handler, %function
Reset_Handler:
    ldr   sp, =_estack              /* 设置主栈指针 */

    /* 拷贝 .data：从 Flash(_sidata=LOADADDR(.data)) 到 RAM(_sdata.._edata)
     * 注意：不能用 __etext（.text 末尾）作源——.rodata 夹在 .text 与
     * .data 的 LMA 之间，用 __etext 会把只读字符串拷进 .data 造成全局变量损坏。*/
    ldr   r0, =_sdata
    ldr   r1, =_edata
    ldr   r2, =_sidata
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
    /* SVCall / PendSV / SysTick 由 FreeRTOS 端口接管，不在此定义弱别名 */
    def_weak_handler DebugMon_Handler

    .weak SystemInit
    .type SystemInit, %function
SystemInit:
    bx lr
    .size SystemInit, .-SystemInit

    .end
