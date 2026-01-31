#!/bin/bash

# CVE 挖掘任务监控和自动重启脚本
# 作者: 小贾
# 日期: 2026-01-31

PROJECT_DIR="/Users/jiajunyu/paper/project/find_cve_client/vuln_repo_miner"
LOG_FILE="$PROJECT_DIR/monitor.log"
PID_FILE="$PROJECT_DIR/cve_mining.pid"

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# 检查进程是否运行
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null; then
            return 0
        else
            rm -f "$PID_FILE"
            return 1
        fi
    else
        return 1
    fi
}

# 启动 CVE 挖掘任务
start_cve_mining() {
    log "启动 CVE 挖掘任务..."
    cd "$PROJECT_DIR"
    
    # 后台运行主任务
    nohup ./run_cve_mining.sh > cve_mining.log 2>&1 &
    PID=$!
    echo "$PID" > "$PID_FILE"
    
    log "CVE 挖掘任务已启动，PID: $PID"
}

# 停止 CVE 挖掘任务
stop_cve_mining() {
    if is_running; then
        PID=$(cat "$PID_FILE")
        log "停止 CVE 挖掘任务 (PID: $PID)..."
        kill "$PID"
        sleep 2
        if ps -p "$PID" > /dev/null; then
            kill -9 "$PID"
            log "强制终止 CVE 挖掘任务"
        fi
        rm -f "$PID FILE"
        log "CVE 挖掘任务已停止"
    else
        log "CVE 挖掘任务未运行"
    fi
}

# 主监控循环
monitor_loop() {
    log "=== CVE 挖掘监控启动 ==="
    
    while true; do
        if ! is_running; then
            log "检测到 CVE 挖掘任务已停止，正在重新启动..."
            start_cve_mining
            log "等待 5 秒钟让任务稳定..."
            sleep 5
        else
            # 检查任务是否正常运行（可选：检查日志文件是否有新内容）
            current_size=$(stat -f%z "$PROJECT_DIR/cve_mining.log" 2>/dev/null || echo 0)
            sleep 30
            new_size=$(stat -f%z "$PROJECT_DIR/cve_mining.log" 2>/dev/null || echo 0)
            
            if [ "$current_size" -eq "$new_size" ]; then
                # 日志没有更新，可能任务卡住了
                log "检测到任务可能卡住（30秒无日志更新），检查进程状态..."
                if is_running; then
                    log "任务仍在运行，继续监控"
                else
                    log "任务已停止，准备重启"
                fi
            fi
        fi
        
        # 每分钟检查一次
        sleep 60
    done
}

# 处理信号
cleanup() {
    log "收到停止信号，正在清理..."
    stop_cve_mining
    log "监控已停止"
    exit 0
}

# 注册信号处理
trap cleanup SIGINT SIGTERM

# 主程序
case "${1:-}" in
    start)
        if is_running; then
            log "CVE 挖掘任务已经在运行"
            exit 1
        else
            start_cve_mining
        fi
        ;;
    stop)
        stop_cve_mining
        ;;
    restart)
        stop_cve_mining
        sleep 2
        start_cve_mining
        ;;
    status)
        if is_running; then
            PID=$(cat "$PID_FILE")
            log "CVE 挖掘任务正在运行 (PID: $PID)"
        else
            log "CVE 挖掘任务未运行"
        fi
        ;;
    monitor)
        monitor_loop
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|monitor}"
        echo "建议使用: $0 monitor 启动监控"
        exit 1
        ;;
esac