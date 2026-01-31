"""命令行入口：按 CVE 记录筛选符合条件的 Maven 仓库。"""

import argparse
import json
import logging
import os
import shutil
from pathlib import Path
from collections import defaultdict

from src.builder import clone_repo_with_retry as clone_repo, build_repo_only
from src.detector import detect_usage
from src.github_search import GitHubSearcher
from src.maven import resolve_dependency_version, parse_version_spec, generate_candidate_versions, version_satisfies
from src.parser import load_vuln_records
from src.utils import ensure_dir, write_jsonl, setup_logger, append_jsonl
from src.intermediate import IntermediateCache
from src.log_utils import logger


def parse_library_coords(cve_library: str):
    """直接解析 groupId/artifactId 格式的 CVE_Library 字段。"""
    if not cve_library or "/" not in cve_library:
        return None
    group_id, artifact_id = cve_library.split("/", 1)
    return {"groupId": group_id, "artifactId": artifact_id}


def group_records_by_library(records):
    """将 CVE 记录按 CVE_Library 分组。"""
    library_groups = defaultdict(list)
    for record in records:
        cve_library = record.get("CVE_Library", "")
        if cve_library:
            library_groups[cve_library].append(record)
    return dict(library_groups)


def copy_repository_to_cve_dirs(repo_full_name, temp_clone_dir, cve_numbers, args):
    """将临时克隆的仓库复制到所有相关 CVE 的目录中。"""
    copied_dirs = {}
    for cve_number in cve_numbers:
        cve_clone_dir = os.path.join(args.workdir, cve_number, repo_full_name.replace("/", "__"))
        # 确保目标目录存在
        os.makedirs(os.path.dirname(cve_clone_dir), exist_ok=True)
        # 如果目标目录已存在，先删除
        if os.path.exists(cve_clone_dir):
            shutil.rmtree(cve_clone_dir)
        # 复制仓库
        shutil.copytree(temp_clone_dir, cve_clone_dir)
        copied_dirs[cve_number] = cve_clone_dir
        logger.info(f"已复制仓库到 {cve_number} 目录", indent=3)
    return copied_dirs


def process_library_group(library_name, cve_records, searcher, args, cache, output_path):
    """处理一个 Library 组的所有 CVE 记录，共享仓库克隆。"""
    logger.info(f"开始处理 Library 组: {library_name} ({len(cve_records)} 个 CVE)", indent=0)
    
    # 解析 Library 坐标
    coords = parse_library_coords(library_name)
    if not coords:
        logger.warning(f"无法解析 Library 坐标: {library_name}", indent=1)
        # 为每个 CVE 生成错误结果
        for record in cve_records:
            cve_number = record.get("CVE_Number", "UNKNOWN")
            error_result = {
                "CVE_Number": cve_number,
                "CVE_Library": library_name,
                "Target_Maven": {},
                "Matches": [],
                "reason": "无法解析 CVE_Library 格式"
            }
            append_jsonl(output_path, error_result)
        return
    
    group_id = coords["groupId"]
    artifact_id = coords["artifactId"]
    
    # 获取所有 CVE 编号
    cve_numbers = [record.get("CVE_Number", "UNKNOWN") for record in cve_records]
    
    # 检查是否已有搜索结果缓存（按 Library 名称）
    library_cache_key = f"LIBRARY_{library_name.replace('/', '__')}"
    if cache.has_search_results(library_cache_key):
        repos = cache.load_search_results(library_cache_key)
        logger.info(f"已从缓存加载搜索结果，Library: {library_name}", indent=1)
    else:
        # 执行 GitHub 搜索
        query_terms = [
            f'{group_id}',
            "filename:pom.xml",
        ]
        query = "+".join(query_terms)
        logger.info(f"GitHub 搜索查询: {query}", indent=1)
        repos = searcher.search_repositories(query, max_repos=args.topk)
        cache.save_search_results(library_cache_key, repos)
        logger.info(f"已保存搜索结果到缓存，Library: {library_name}", indent=1)
    
    if not repos:
        logger.warning(f"未找到候选仓库，Library: {library_name}", indent=1)
        # 为每个 CVE 生成无结果
        for record in cve_records:
            cve_number = record.get("CVE_Number", "UNKNOWN")
            no_result = {
                "CVE_Number": cve_number,
                "CVE_Library": library_name,
                "Target_Maven": {"groupId": group_id, "artifactId": artifact_id, "version": record.get("CVE_Library_version", "")},
                "Matches": [],
                "reason": "未找到候选仓库"
            }
            append_jsonl(output_path, no_result)
        return
    
    logger.info(f"预处理 {len(repos)} 个仓库用于 Library: {library_name}", indent=1)
    
    # 创建临时工作目录
    temp_workdir = os.path.join(args.workdir, "_temp_library_processing")
    os.makedirs(temp_workdir, exist_ok=True)
    
    # 处理每个候选仓库
    for repo in repos:
        repo_full = repo["full_name"]
        repo_url = repo["html_url"]
        
        logger.info(f"预处理仓库: {repo_full}", indent=2)
        # 克隆到临时目录
        temp_clone_dir = os.path.join(temp_workdir, repo_full.replace("/", "__"))

        # 为每个 CVE 进行独立的验证
        for record in cve_records:
            cve_number = record.get("CVE_Number", "UNKNOWN")
            cve_version = record.get("CVE_Library_version", "")
            cve_class = record.get("CVE_Class", "")
            cve_method = record.get("CVE_Method", "")
            
            # 检查是否已经处理过这个仓库（针对这个 CVE）
            existing_status = cache.load_clone_status(cve_number, repo_full)
            if existing_status and existing_status.get("status") in ["kept", "deleted", "failed"]:
                status_type = existing_status.get("status")
                reason_key = "delete_reason" if status_type == "deleted" else "reason"
                reason = existing_status.get(reason_key, "unknown")
                logger.info(f"跳过已处理（{status_type}）的仓库 {repo_full}: {reason}", indent=2)
                continue
            else:

                if os.path.exists(temp_clone_dir):
                    logger.info(f"仓库已存在于临时目录: {temp_clone_dir}", indent=3)
                else:
                    # 克隆仓库到临时目录
                    clone_info = clone_repo(repo_url, temp_clone_dir, timeout=args.timeout)
                    if not clone_info["cloned"]:
                        delete_reason = "克隆失败: " + clone_info.get("reason", "unknown")
                        logger.info(f"跳过仓库 {repo_full}: {delete_reason}", indent=3)
                        continue

                # 将临时克隆的仓库复制到所有相关 CVE 的目录中
                copied_dirs = copy_repository_to_cve_dirs(repo_full, temp_clone_dir, cve_numbers, args)
            
            # 获取该 CVE 对应的克隆目录
            cve_clone_dir = copied_dirs[cve_number]
            
            # 解析依赖版本
            pom_found, dep_info = resolve_dependency_version(cve_clone_dir, group_id, artifact_id)
            if not pom_found:
                delete_reason = "未找到 pom.xml 文件"
                cache.mark_repo_deleted(cve_number, repo_full, args.workdir, delete_reason)
                logger.info(f"跳过仓库 {repo_full}: {delete_reason}", indent=3)
                continue

            resolved_version = dep_info.get("resolved_version")
            dependency_source = dep_info.get("source", "unknown")
            version_match = False
            reason = "未解析到版本"
            if resolved_version:
                version_spec = parse_version_spec(cve_version)
                version_match = version_satisfies(resolved_version, version_spec)
                reason = dep_info.get("reason")

            if not version_match:
                delete_reason = f"版本不匹配: {reason}"
                cache.mark_repo_deleted(cve_number, repo_full, args.workdir, delete_reason)
                logger.info(f"跳过仓库 {repo_full}: {delete_reason}", indent=3)
                continue

            # 检测源码使用
            usage_info = detect_usage(cve_clone_dir, cve_class, cve_method)
            if not usage_info["uses_target_class"] or not usage_info["uses_target_method"]:
                delete_reason = "未找到目标类或方法调用"
                cache.mark_repo_deleted(cve_number, repo_full, args.workdir, delete_reason)
                logger.info(f"跳过仓库 {repo_full}: {delete_reason}", indent=3)
                continue

            # 执行构建验证
            build_info = build_repo_only(cve_clone_dir, timeout=args.timeout)
            if not build_info["build_success"]:
                delete_reason = f"构建失败: {build_info.get('reason', 'unknown')}"
                cache.mark_repo_deleted(cve_number, repo_full, args.workdir, delete_reason)
                logger.info(f"跳过仓库 {repo_full}: {delete_reason}", indent=3)
                continue

            # 仓库满足所有条件，保留并记录
            match = {
                "repo": repo_full,
                "repo_url": repo_url,
                "commit": clone_info.get("commit"),
                "pom_found": pom_found,
                "dependency_version_resolved": resolved_version,
                "dependency_version_source": dependency_source,
                "version_match": version_match,
                "version_match_reason": reason,
                "uses_target_class": usage_info["uses_target_class"],
                "uses_target_method": usage_info["uses_target_method"],
                "build_success": build_info["build_success"],
                "build_cmd": build_info.get("build_cmd"),
                "evidence": {
                    "class_hit_files": usage_info.get("class_hit_files", []),
                    "method_call_snippets": usage_info.get("method_call_snippets", []),
                },
            }

            # 保存保留状态
            cache.mark_repo_kept(cve_number, repo_full, build_info, version_match, usage_info)

            logger.info(f"保留仓库 {repo_full} 用于 CVE {cve_number}", indent=3)
            
            # 实时追加保存这个匹配结果
            temp_result = {
                "CVE_Number": cve_number,
                "CVE_Library": library_name,
                "Target_Maven": {"groupId": group_id, "artifactId": artifact_id, "version": cve_version},
                "Matches": [match],
                "best_match": repo_full
            }
            append_jsonl(output_path, temp_result)
        
        # 清理临时克隆目录（可选，为了节省空间）
        shutil.rmtree(temp_clone_dir, ignore_errors=True)
    
    # 清理临时工作目录（可选）
    shutil.rmtree(temp_workdir, ignore_errors=True)
    
    logger.info(f"Library 组 {library_name} 处理完成", indent=0)


def main():
    parser = argparse.ArgumentParser(description="CVE Maven 仓库挖掘工具")
    parser.add_argument("--input", default="vul_info.json", help="输入 JSON/JSONL 文件")
    parser.add_argument("--output", default="outputs/result.jsonl", help="输出 JSONL 文件")
    parser.add_argument("--topk", type=int, default=1000, help="每个 CVE 最多处理的仓库数量（GitHub API 限制: 1000）")
    parser.add_argument("--workdir", default=".workdir", help="克隆仓库的工作目录")
    parser.add_argument("--timeout", type=int, default=300, help="克隆和构建超时时间（秒，默认300秒）")
    args = parser.parse_args()

    setup_logger()
    ensure_dir(args.workdir)
    output_path = Path(args.output)
    ensure_dir(str(output_path.parent))

    # 清空输出文件（新运行）
    if os.path.exists(args.output):
        logger.info(f"发现现有输出文件，将覆盖内容", indent=0)
    open(args.output, 'w').close()
    logger.info(f"创建新的输出文件: {args.output}", indent=0)

    records = load_vuln_records(args.input)
    
    # 按 Library 分组
    library_groups = group_records_by_library(records)
    logger.info(f"共 {len(records)} 个 CVE，分组为 {len(library_groups)} 个 Library", indent=0)
    
    searcher = GitHubSearcher(token="")
    cache = IntermediateCache(base_dir="intermediate")

    # 处理每个 Library 组
    for library_name, cve_records in library_groups.items():
        process_library_group(library_name, cve_records, searcher, args, cache, str(output_path))

    logger.info(f"所有 Library 组处理完成，结果已保存到 {args.output}", indent=0)


if __name__ == "__main__":
    main()