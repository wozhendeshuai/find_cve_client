#!/usr/bin/env python3
"""
监控 CVE 仓库挖掘工具的运行状态
每15分钟检查一次输出文件和日志
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path

def monitor_cve_mining():
    """监控 CVE 挖掘工具的运行状态"""
    
    # 配置路径
    project_dir = Path("/Users/jiajunyu/paper/project/find_cve_client/vuln_repo_miner")
    output_file = project_dir / "outputs" / "result.jsonl"
    workdir = project_dir / ".workdir"
    intermediate_dir = project_dir / "intermediate"
    
    print(f"=== CVE 挖掘工具监控报告 ===")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 1. 检查输出文件
    if output_file.exists():
        with open(output_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_cves = len(lines)
        matched_cves = 0
        total_matches = 0
        
        for line in lines:
            if line.strip():
                try:
                    result = json.loads(line)
                    matches = result.get('Matches', [])
                    if matches:
                        matched_cves += 1
                        total_matches += len(matches)
                except json.JSONDecodeError:
                    continue
        
        print(f"📊 输出文件状态:")
        print(f"   - 总 CVE 数量: {total_cves}")
        print(f"   - 找到匹配的 CVE: {matched_cves}")
        print(f"   - 总匹配仓库数: {total_matches}")
        print()
    else:
        print("📊 输出文件: 尚未创建")
        print()
    
    # 2. 检查工作目录
    if workdir.exists():
        cve_dirs = [d for d in workdir.iterdir() if d.is_dir()]
        print(f"📁 工作目录状态:")
        print(f"   - 正在处理的 CVE 目录数: {len(cve_dirs)}")
        if len(cve_dirs) <= 5:
            for cve_dir in cve_dirs:
                repo_count = len([r for r in cve_dir.iterdir() if r.is_dir()])
                print(f"     - {cve_dir.name}: {repo_count} 个仓库")
        print()
    
    # 3. 检查中间结果
    if intermediate_dir.exists():
        search_dir = intermediate_dir / "search_results"
        clone_dir = intermediate_dir / "clone_status"
        
        search_count = len(list(search_dir.glob("*.json"))) if search_dir.exists() else 0
        clone_count = len(list(clone_dir.glob("*"))) if clone_dir.exists() else 0
        
        print(f"💾 中间结果缓存:")
        print(f"   - 搜索结果缓存: {search_count} 个 CVE")
        print(f"   - 克隆状态缓存: {clone_count} 个 CVE 目录")
        print()
    
    # 4. 检查最近的日志（如果有）
    log_files = list(project_dir.glob("*.log"))
    if log_files:
        latest_log = max(log_files, key=os.path.getmtime)
        print(f"📝 最近日志文件: {latest_log.name}")
        # 读取最后几行
        try:
            with open(latest_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    print("   最后几行日志:")
                    for line in lines[-3:]:
                        print(f"     {line.strip()}")
        except Exception as e:
            print(f"   读取日志失败: {e}")
        print()
    
    print("=== 监控结束 ===")

if __name__ == "__main__":
    monitor_cve_mining()