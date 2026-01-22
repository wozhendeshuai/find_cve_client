"""构建模块：clone 仓库并执行 Maven 构建。"""

import logging
import os
import subprocess
import time


MAX_REPO_SIZE_MB = 300


def _run(cmd, cwd=None, timeout=120):
    """执行命令并返回结果。"""
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def _repo_size_mb(path: str) -> int:
    """获取仓库大小（MB）。"""
    result = _run(["du", "-sm", path])
    if result.returncode != 0:
        return 0
    size_str = result.stdout.split()[0]
    return int(size_str)


def build_repo(repo_url: str, clone_dir: str, timeout: int = 120):
    """克隆并构建仓库，记录构建信息。"""
    if os.path.exists(clone_dir):
        logging.info("Repo already cloned: %s", clone_dir)
    else:
        os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
        logging.info("Cloning %s", repo_url)
        try:
            result = _run(["git", "clone", "--depth", "1", repo_url, clone_dir], timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"cloned": False, "build_success": False, "reason": "clone_timeout"}
        if result.returncode != 0:
            logging.error("Clone failed: %s", result.stderr[-200:])
            return {"cloned": False, "build_success": False, "reason": "clone_failed"}

    size_mb = _repo_size_mb(clone_dir)
    if size_mb > MAX_REPO_SIZE_MB:
        logging.warning("Repo too large (%s MB), skipping", size_mb)
        return {"cloned": True, "build_success": False, "reason": "repo_too_large"}

    commit = None
    try:
        commit_result = _run(["git", "rev-parse", "HEAD"], cwd=clone_dir)
        if commit_result.returncode == 0:
            commit = commit_result.stdout.strip()
    except Exception:
        pass

    mvnw_path = os.path.join(clone_dir, "mvnw")
    if os.path.exists(mvnw_path):
        cmd = ["./mvnw", "-q", "-DskipTests", "package"]
    else:
        cmd = ["mvn", "-q", "-DskipTests", "package"]

    logging.info("Building with %s", " ".join(cmd))
    start = time.time()
    try:
        result = _run(cmd, cwd=clone_dir, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "cloned": True,
            "commit": commit,
            "build_success": False,
            "build_cmd": " ".join(cmd),
            "reason": "build_timeout",
        }
    duration = time.time() - start
    if result.returncode != 0:
        logging.error("Build failed in %.2fs: %s", duration, result.stderr[-200:])
        return {
            "cloned": True,
            "commit": commit,
            "build_success": False,
            "build_cmd": " ".join(cmd),
            "reason": result.stderr[-200:],
        }

    return {
        "cloned": True,
        "commit": commit,
        "build_success": True,
        "build_cmd": " ".join(cmd),
    }
