#!/usr/bin/env bash
# =====================================================================
# 在 QEMU (mps2-an385, Cortex-M3) 上仿真运行 app.elf
#
# 用法：
#   ./build.sh qemu     # 先构建（产物在 build-qemu/）
#   ./run_qemu.sh       # 仿真运行，串口输出直接打到终端
#
# 退出：固件是 FreeRTOS 调度器，永不返回。
#   - Ctrl+C            退出 QEMU
#   - Ctrl+A 然后 X     QEMU 的"强制退出"快捷键（-nographic 下）
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")"

ELF=build-qemu/app.elf
if [[ ! -f "$ELF" ]]; then
    echo "错误：找不到 $ELF，请先运行 ./build.sh qemu" >&2
    exit 1
fi

if ! command -v qemu-system-arm >/dev/null 2>&1; then
    echo "错误：找不到 qemu-system-arm，请先安装 QEMU（apt install qemu-system-arm）。" >&2
    exit 1
fi

echo "在 QEMU mps2-an385 (Cortex-M3, 25MHz) 上运行 $ELF ..."
echo "退出：Ctrl+C 或 Ctrl+A 然后 X"
echo

# -M mps2-an385   ARM MPS2 AN385 FPGA 镜像（Cortex-M3，无 FPU）
# -nographic      串口输出到终端（CMSDK APB UART @ 0x40004000 → serial_hd(0)）
# -kernel app.elf QEMU 的 armv7m_load_kernel 把 ELF 加载到 0x0，
#                 复位时从向量表读 SP/PC（见 port/startup_qemu.s 注释）
exec qemu-system-arm \
    -M mps2-an385 \
    -nographic \
    -kernel "$ELF"
