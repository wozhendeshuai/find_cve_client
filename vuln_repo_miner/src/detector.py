"""源码检测模块：文本 + AST 解析检测类/方法调用。"""

import logging
import os
import re
import subprocess
from typing import Dict, List

import javalang


def _rg_files(repo_path: str, pattern: str) -> List[str]:
    """优先用 ripgrep 获取候选 Java 文件列表。"""
    cmd = ["rg", "-l", pattern, repo_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        logging.warning("未找到 rg 工具，回退到 os.walk 扫描")
        return []
    if result.returncode not in (0, 1):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip().endswith(".java")]


def _fallback_java_files(repo_path: str) -> List[str]:
    """没有 rg 时的兜底扫描。"""
    java_files = []
    for root, _, files in os.walk(repo_path):
        for name in files:
            if name.endswith(".java"):
                java_files.append(os.path.join(root, name))
    return java_files


def _extract_method_name(signature: str) -> str:
    """从方法签名里解析方法名。"""
    if not signature:
        return ""
    name = signature.split("(")[0]
    return name.split(":")[0].strip()


def detect_usage(repo_path: str, target_class: str, target_method: str) -> Dict[str, object]:
    """检测目标类与方法是否真实调用。"""
    short_class = target_class.split(".")[-1] if target_class else ""
    method_name = _extract_method_name(target_method)
    class_hit_files: List[str] = []
    method_snippets: List[str] = []
    uses_class = False
    uses_method = False

    files = _rg_files(repo_path, short_class) if short_class else []
    if not files:
        files = _fallback_java_files(repo_path)

    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except Exception:
            continue
        if short_class and short_class not in content:
            continue
        class_hit_files.append(os.path.relpath(file_path, repo_path))
        uses_class = True
        if method_name and method_name in content:
            snippet_lines = []
            for line in content.splitlines():
                if method_name in line and short_class in line:
                    snippet_lines.append(line.strip())
            method_snippets.extend(snippet_lines[:3])
        try:
            tree = javalang.parse.parse(content)
        except Exception:
            continue
        if method_name:
            for _, node in tree.filter(javalang.tree.MethodInvocation):
                if node.member == method_name:
                    uses_method = True
                    if node.qualifier:
                        method_snippets.append(f"{node.qualifier}.{node.member}(...)")
        if uses_method:
            break

    return {
        "uses_target_class": uses_class,
        "uses_target_method": uses_method,
        "class_hit_files": class_hit_files,
        "method_call_snippets": list(dict.fromkeys(method_snippets)),
    }