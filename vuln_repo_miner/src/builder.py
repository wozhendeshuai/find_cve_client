"""构建模块：clone 仓库并执行 Maven 构建。"""

import logging
import os
import subprocess
import time


MAX_REPO_SIZE_MB = 512


def _run(cmd, cwd=None, timeout=300):
    """执行命令并返回结果。"""
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _repo_size_mb(path: str) -> int:
    """获取仓库大小（MB）。"""
    result = _run(["du", "-sm", path])
    if result.returncode != 0:
        return 0
    size_str = result.stdout.split()[0]
    return int(size_str)


def clone_repo_with_retry(repo_url: str, clone_dir: str, timeout: int = 300, max_retries: int = 3):
    """带重试机制的仓库克隆，专门优化国内网络环境。"""
    if os.path.exists(clone_dir):
        logging.info("仓库已克隆: %s", clone_dir)
        return {"cloned": True, "reason": "already_exists", "commit": None}
    
    os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
    
    for attempt in range(max_retries):
        if attempt > 0:
            wait_time = 5 + attempt * 5  # 第1次等5秒，第2次等10秒，第3次等15秒
            logging.warning("克隆失败，第 %d 次重试（等待 %d 秒后）...", attempt, wait_time)
            time.sleep(wait_time)
        
        logging.info("正在克隆 %s (尝试 %d/%d)", repo_url, attempt + 1, max_retries)
        try:
            result = _run(["git", "clone", "--depth", "1", repo_url, clone_dir], timeout=timeout)
        except subprocess.TimeoutExpired:
            error_msg = f"克隆超时（{timeout}秒）"
            logging.error("克隆失败: %s", error_msg)
            if attempt == max_retries - 1:
                return {"cloned": False, "reason": error_msg}
            continue
        
        if result.returncode != 0:
            # 提取具体的错误信息
            error_output = result.stderr.strip() if result.stderr else "未知错误"
            if len(error_output) > 200:
                error_output = error_output[-200:] + "..."
            
            # 判断常见错误类型
            if "Connection timed out" in error_output or "Could not read from remote repository" in error_output:
                error_msg = f"网络连接问题: {error_output}"
            elif "Repository not found" in error_output:
                error_msg = f"仓库不存在: {error_output}"
            else:
                error_msg = f"克隆失败: {error_output}"
            
            logging.error("克隆失败: %s", error_msg)
            if attempt == max_retries - 1:
                return {"cloned": False, "reason": error_msg}
            continue
        
        # 克隆成功，检查仓库大小
        size_mb = _repo_size_mb(clone_dir)
        if size_mb > MAX_REPO_SIZE_MB:
            logging.warning("仓库过大 (%s MB)，跳过", size_mb)
            # 清理已克隆的目录
            try:
                import shutil
                shutil.rmtree(clone_dir)
            except Exception as e:
                logging.warning("清理过大仓库失败: %s", e)
            return {"cloned": False, "reason": f"仓库过大 ({size_mb} MB)"}
        
        # 获取提交哈希
        commit = None
        try:
            commit_result = _run(["git", "rev-parse", "HEAD"], cwd=clone_dir)
            if commit_result.returncode == 0:
                commit = commit_result.stdout.strip()
        except Exception as e:
            logging.warning("获取提交哈希失败: %s", e)
        
        logging.info("仓库克隆成功: %s", repo_url)
        return {"cloned": True, "commit": commit, "reason": "success"}
    
    # 理论上不会到达这里，但为了安全起见
    return {"cloned": False, "reason": "未知错误"}


def build_repo_only(clone_dir: str, timeout: int = 300):
    """只执行构建，假设仓库已经克隆。"""
    mvnw_path = os.path.join(clone_dir, "mvnw")
    if os.path.exists(mvnw_path):
        cmd = ["./mvnw", "-q", "-DskipTests", "package"]
    else:
        cmd = ["mvn", "-q", "-DskipTests", "package"]

    logging.info("使用命令构建: %s", " ".join(cmd))
    start = time.time()
    try:
        result = _run(cmd, cwd=clone_dir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "build_success": False,
            "build_cmd": " ".join(cmd),
            "reason": "构建超时",
        }
    duration = time.time() - start
    if result.returncode != 0:
        # 提取构建错误信息
        error_output = result.stderr.strip() if result.stderr else "未知构建错误"
        if len(error_output) > 200:
            error_output = error_output[-200:] + "..."
        logging.error("构建失败，耗时 %.2fs: %s", duration, error_output)
        return {
            "build_success": False,
            "build_cmd": " ".join(cmd),
            "reason": error_output,
        }

    return {
        "build_success": True,
        "build_cmd": " ".join(cmd),
    }


def build_repo_from_dir(clone_dir: str, timeout: int = 300):
    """从已克隆的目录执行构建。"""
    return build_repo_only(clone_dir, timeout)


def clone_and_build_repo(repo_url: str, clone_dir: str, timeout: int = 300, max_retries: int = 3):
    """克隆并构建仓库（兼容旧代码，不推荐使用）。"""
    clone_result = clone_repo_with_retry(repo_url, clone_dir, timeout, max_retries)
    if not clone_result["cloned"]:
        return {"cloned": False, "build_success": False, "reason": clone_result.get("reason", "unknown")}
    
    build_result = build_repo_only(clone_dir, timeout)
    return {
        "cloned": True,
        "commit": clone_result.get("commit"),
        "build_success": build_result["build_success"],
        "build_cmd": build_result.get("build_cmd"),
        "reason": build_result.get("reason", "")
    }