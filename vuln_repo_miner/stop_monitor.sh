#!/bin/bash

# 停止监控脚本
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/monitor_cve_mining.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null; then
        echo "正在停止监控进程 (PID: $PID)..."
        kill "$PID"
        # 等待进程结束
        sleep 2
        if ps -p "$PID" > /dev/null; then
            echo "强制终止监控进程..."
            kill -9 "$PID"
        fi
    fi
    rm -f "$PID_FILE"
    echo "监控已停止"
else
    echo "未找到监控进程"
fi

# 停止 CVE 挖掘进程
CVE_PID_FILE="$SCRIPT_DIR/cve_mining.pid"
if [ -f "$CVE_PID_FILE" ]; then
    CVE_PID=$(cat "$CVE_PID_FILE")
    if ps -p "$CVE_PID" > /dev/null; then
        echo "正在停止 CVE 挖掘进程 (PID: $CVE_PID)..."
        kill "$CVE_PID"
        sleep 2
        if ps -p "$CVE_PID" > /dev/null; then
            echo "强制终止 CVE 挖掘进程..."
            kill -9 "$CVE_PID"
        fi
    fi
    rm -f "$CVE_PID_FILE"
fi