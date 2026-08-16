#!/usr/bin/env bash
# =====================================================================
# 在 QEMU (mps2-an385, Cortex-M3) 上仿真运行 app.elf
#
# 用法：
#   ./build.sh qemu        # 先构建（产物在 build-qemu/）
#   ./run_qemu.sh          # 仿真运行，串口输出直接打到终端
#   ./run_qemu.sh --debug  # 调试模式：-S 让 CPU 停在复位处，并在 :1234（可用
#                          # QEMU_GDB_PORT 覆盖）开 GDB stub，等 GDB attach 后才
#                          # 开始（.vscode/launch.json 的 "Debug 16 Embedded
#                          # (QEMU)" preLaunchTask 用此模式）
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

# --debug：-gdb tcp::PORT 开 GDB server（端口 QEMU_GDB_PORT，默认 1234，
#          与 .vscode/launch.json 的 miDebuggerServerAddress 保持一致）；
#          -S 让 CPU 停在复位处，等 GDB attach 并 continue 后才开始跑。
#          没有它固件几秒内就跑完，attach 时已经错过了入口。
GDB_PORT=${QEMU_GDB_PORT:-1234}
DEBUG_FLAGS=()
case "${1:-}" in
    --debug|-d)
        pkill -f 'qemu-system-arm.*mps2-an385' 2>/dev/null || true  # 避免旧实例占着端口
        sleep 0.3
        DEBUG_FLAGS=(-S "-gdb" "tcp::${GDB_PORT}")
        ;;
    "") ;;
    *) echo "未知参数：$1（仅支持 --debug）" >&2; exit 2;;
esac

if (( ${#DEBUG_FLAGS[@]} )); then
    echo "在 QEMU mps2-an385 (Cortex-M3, 25MHz) 上运行 $ELF ... [调试模式]"
    echo "GDB stub: localhost:${GDB_PORT}，CPU 已停在复位处，等 GDB attach 后 continue"
else
    echo "在 QEMU mps2-an385 (Cortex-M3, 25MHz) 上运行 $ELF ..."
    echo "退出：Ctrl+C 或 Ctrl+A 然后 X"
fi
echo

# -M mps2-an385   ARM MPS2 AN385 FPGA 镜像（Cortex-M3，无 FPU）
# -nographic      串口输出到终端（CMSDK APB UART @ 0x40004000 → serial_hd(0)）
# -kernel app.elf QEMU 的 armv7m_load_kernel 把 ELF 加载到 0x0，
#                 复位时从向量表读 SP/PC（见 port/startup_qemu.s 注释）
# -s / -S         GDB 调试（仅 --debug）
exec qemu-system-arm \
    -M mps2-an385 \
    -nographic \
    -kernel "$ELF" \
    "${DEBUG_FLAGS[@]}"
