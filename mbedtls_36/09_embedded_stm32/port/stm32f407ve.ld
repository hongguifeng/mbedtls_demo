/*
 * STM32F407VE 链接脚本（GNU ld 语法）
 *
 * 内存布局：
 *   FLASH : 1 MB @ 0x08000000   （代码 + 只读数据 + .data 的初始值）
 *   RAM   : 192 KB @ 0x20000000 （.data 运行副本 + .bss + 堆栈 + FreeRTOS 堆）
 *
 * 关键 section：
 *   .isr_vector  向量表，必须位于 Flash 起始（复位后 PC 从此读取）
 *   .data        有初始值的全局/静态变量，Flash 存初值、RAM 存运行值
 *   .bss         未初始化全局/静态变量，启动时清零
 *   _estack      主栈顶（RAM 末尾）
 */

ENTRY(Reset_Handler)

/* 各段起止符号，供 startup 与调试使用 */
_estack = ORIGIN(RAM) + LENGTH(RAM);   /* 主栈顶 */
_min_heap_size = 0x200;                /* 至少 512B 堆（newlib 需要）*/

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
}

SECTIONS
{
    /* 向量表：Flash 最开头 */
    .isr_vector :
    {
        . = ALIGN(4);
        KEEP(*(.isr_vector))
        . = ALIGN(4);
    } >FLASH

    /* 代码 */
    .text :
    {
        . = ALIGN(4);
        *(.text)
        *(.text*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)

        KEEP (*(.init))
        KEEP (*(.fini))

        . = ALIGN(4);
        _etext = .;
        __etext = .;          /* startup 用 __etext 作为 .data 拷贝源起点 */
    } >FLASH

    /* 只读数据 */
    .rodata :
    {
        . = ALIGN(4);
        *(.rodata)
        *(.rodata*)
        . = ALIGN(4);
    } >FLASH

    /* C++ 构造/析构（本项目为纯 C，保留以防万一）*/
    .preinit_array :
    {
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP (*(.preinit_array*))
        PROVIDE_HIDDEN (__preinit_array_end = .);
    } >FLASH
    .init_array :
    {
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array*))
        PROVIDE_HIDDEN (__init_array_end = .);
    } >FLASH
    .fini_array :
    {
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT(.fini_array.*)))
        KEEP (*(.fini_array*))
        PROVIDE_HIDDEN (__fini_array_end = .);
    } >FLASH

    /* .data 的 Flash 初始值区（startup 从这里拷贝到 RAM）*/
    _sidata = LOADADDR(.data);
    .data :
    {
        . = ALIGN(4);
        _sdata = .;
        *(.data)
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } >RAM AT> FLASH

    /* .bss：未初始化，startup 清零 */
    .bss :
    {
        . = ALIGN(4);
        __bss_start__ = .;
        _sbss = .;
        *(.bss)
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
        _ebss = .;
        end = .;              /* newlib-nano _sbrk 的堆起点符号 */
    } >RAM

    /* 堆：从 end 到 RAM 末尾（newlib malloc 使用）*/
    ._heap :
    {
        . = ALIGN(8);
        __heap_start__ = .;
        . = ORIGIN(RAM) + LENGTH(RAM);
        __heap_end__ = .;
    } >RAM

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.attributes)
    }

    /* 断言：确保没有溢出 */
    ASSERT(__heap_end__ <= ORIGIN(RAM) + LENGTH(RAM), "region RAM overflowed")
}
