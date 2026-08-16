/*
 * QEMU mps2-an385 链接脚本（GNU ld 语法）
 *
 * 与 stm32f407ve.ld 的区别：
 *   FLASH : 1 MB @ 0x00000000   （QEMU MPS2 的 SSRAM1，充当"Flash"，
 *                                armv7m_load_kernel 把 ELF 加载到这里）
 *   RAM   : 192 KB @ 0x20000000 （SSRAM2&3 的前 192KB，与 STM32F407VE 一致，
 *                                便于对比两种构建的体积）
 *
 * 其余 section 布局与符号（_estack/_sdata/_edata/__etext/__bss_start__/
 * __bss_end__/end/__heap_start__/__heap_end__）与 STM32 版完全相同，
 * startup_qemu.s 直接复用同一套拷贝/清零逻辑。
 */

ENTRY(Reset_Handler)

/* 各段起止符号，供 startup 与调试使用 */
_estack = ORIGIN(RAM) + LENGTH(RAM);   /* 主栈顶 */
_min_heap_size = 0x200;                /* 至少 512B 堆（newlib 需要）*/

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 1024K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
}

SECTIONS
{
    /* 向量表：Flash 最开头（QEMU M-profile 复位时从 0x0/0x4 读 SP/PC）*/
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
        __etext = .;          /* .text 末尾（仅供调试；.data 拷贝源是 _sidata）*/
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
        *(ARM.exidx)
        *(.ARM.exidx*)
        *(.ARM.attributes)
    }
}
