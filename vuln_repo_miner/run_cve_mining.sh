#!/bin/bash

# CVE 挖掘主运行脚本
# 用于被监控脚本调用

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="logs/cve_mining_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs outputs

echo "[$(date)] 开始 CVE 挖掘任务..." | tee -a "$LOG_FILE"
echo "输入文件: $1" | tee -a "$LOG_FILE"
echo "输出文件: $2" | tee -a "$LOG_FILE"

# 运行主程序
python3 main.py --input "$1" --output "$2" 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
echo "[$(date)] CVE 挖掘任务结束，退出码: $EXIT_CODE" | tee -a "$LOG_FILE"

exit $EXIT_CODE