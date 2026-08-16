#!/usr/bin/env bash
# =====================================================================
# 在 QEMU (mps2-an385, Cortex-M3) 上仿真运行 app.elf
#
# 用法：
#   ./build.sh qemu        # 先构建（产物在 build-qemu/）
#   ./run_qemu.sh          # 仿真运行，串口输出直接打到终端
#   ./run_qemu.sh --debug  # 调试模式（分离启动，本脚本立即退出）：-S 让 CPU 停在
#                          # 复位处、:1234（可用 QEMU_GDB_PORT 覆盖）开 GDB stub，
#                          # 串口 → build-qemu/qemu_debug.log；.vscode/launch.json
#                          # 的 "Debug 09 Embedded (QEMU)" preLaunchTask 用此模式
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

GDB_PORT=${QEMU_GDB_PORT:-1234}   # 默认与 launch.json miDebuggerServerAddress 一致
DEBUG=0
case "${1:-}" in
    --debug|-d) DEBUG=1 ;;
    "") ;;
    *) echo "未知参数：$1（仅支持 --debug）" >&2; exit 2;;
esac

# -M mps2-an385   ARM MPS2 AN385 FPGA 镜像（Cortex-M3，无 FPU）
# -nographic      串口输出到 stdout（CMSDK APB UART @ 0x40004000 → serial_hd(0)）
# -kernel app.elf QEMU 的 armv7m_load_kernel 把 ELF 加载到 0x0，
#                 复位时从向量表读 SP/PC（见 port/startup_qemu.s 注释）
if (( ! DEBUG )); then
    echo "在 QEMU mps2-an385 (Cortex-M3, 25MHz) 上运行 $ELF ..."
    echo "退出：Ctrl+C 或 Ctrl+A 然后 X"
    echo
    exec qemu-system-arm \
        -M mps2-an385 \
        -nographic \
        -kernel "$ELF"
fi

# --debug 模式：作为 .vscode/launch.json "Debug 09 Embedded (QEMU)" 的 preLaunchTask。
# 关键：preLaunchTask 必须【自己退出】，GDB 才会开始 attach——所以这里把 QEMU
# 分离（setsid）到后台拉起，等 GDB stub 端口就绪后脚本就退出：
#   -S              CPU 停在复位处，GDB attach 并 continue 后才开始跑（没有它
#                   固件几秒内就跑完，attach 时已错过入口）
#   -gdb tcp::PORT  GDB stub（默认 :1234，与 launch.json 一致）
#   串口输出         → build-qemu/qemu_debug.log（tail -f 查看固件输出）
pkill -f 'qemu-system-arm.*mps2-an385' 2>/dev/null || true  # 避免旧实例占着端口
sleep 0.3
LOG=build-qemu/qemu_debug.log
: > "$LOG"
echo "分离启动 QEMU：mps2-an385 (Cortex-M3, 25MHz) + $ELF"
echo "串口日志：$(pwd)/$LOG   （tail -f 查看固件输出）"
echo "GDB stub: localhost:${GDB_PORT}，CPU 停在复位处，等 GDB attach 后 continue"
setsid qemu-system-arm \
    -M mps2-an385 \
    -nographic \
    -kernel "$ELF" \
    -S -gdb "tcp::${GDB_PORT}" \
    > "$LOG" 2>&1 &
# 等 GDB stub 就绪（最多 15 s）再退出，保证 preLaunchTask 结束后
# GDB attach 立即可连。探测用的短连接会被 QEMU 直接丢弃，不影响真正 attach。
up=0
for _ in $(seq 1 150); do
    if (exec 3<>/dev/tcp/127.0.0.1/"${GDB_PORT}") 2>/dev/null; then
        up=1
        break
    fi
    sleep 0.1
done
if (( ! up )); then
    echo "GDB stub (localhost:${GDB_PORT}) 15 s 内未就绪，QEMU 日志尾部：" >&2
    cat "$LOG" >&2
    exit 1
fi
echo "就绪：GDB 可 attach localhost:${GDB_PORT}"
