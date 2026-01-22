"""命令行入口：按 CVE 记录筛选符合条件的 Maven 仓库。"""

import argparse
import json
import logging
import os
from pathlib import Path

from src.builder import build_repo
from src.detector import detect_usage
from src.github_search import GitHubSearcher
from src.mapping import load_mapping, library_to_maven_coords
from src.maven import resolve_dependency_version, parse_version_spec, generate_candidate_versions, version_satisfies
from src.parser import load_vuln_records
from src.utils import ensure_dir, write_jsonl, setup_logger


def process_record(record, searcher, mapping, args):
    """处理单条漏洞记录并输出匹配结果。"""
    cve_number = record.get("CVE_Number", "UNKNOWN")
    cve_library = record.get("CVE_Library", "")
    cve_version = record.get("CVE_Library_version", "")
    cve_class = record.get("CVE_Class", "")
    cve_method = record.get("CVE_Method", "")

    result = {
        "CVE_Number": cve_number,
        "CVE_Library": cve_library,
        "Target_Maven": {},
        "Matches": [],
    }

    if not cve_library:
        logging.warning("CVE_Library missing for %s", cve_number)
        result["reason"] = "Missing CVE_Library"
        return result

    coords = library_to_maven_coords(cve_library, mapping)
    if not coords:
        logging.warning("Unable to map CVE_Library for %s: %s", cve_number, cve_library)
        result["reason"] = "Unable to map CVE_Library"
        return result

    group_id = coords["groupId"]
    artifact_id = coords["artifactId"]
    result["Target_Maven"] = {
        "groupId": group_id,
        "artifactId": artifact_id,
        "version": cve_version,
    }

    version_spec = parse_version_spec(cve_version)
    candidate_versions = generate_candidate_versions(group_id, artifact_id, version_spec)
    if candidate_versions:
        logging.info("Candidate versions for %s:%s => %s", group_id, artifact_id, candidate_versions[:5])

    query_terms = [
        f'"{artifact_id}"',
        "pom.xml",
        "language:Java",
    ]
    if cve_class:
        short_class = cve_class.split(".")[-1]
        query_terms.append(f'"{short_class}"')
    query = " ".join(query_terms)

    repos = searcher.search_repositories(query, max_repos=args.topk)
    if not repos:
        result["reason"] = "No candidate repositories found"
        return result

    for repo in repos:
        if len(result["Matches"]) >= 10:
            break
        repo_full = repo["full_name"]
        repo_url = repo["html_url"]
        logging.info("Processing repo %s", repo_full)

        clone_dir = os.path.join(args.workdir, repo_full.replace("/", "__"))
        build_info = build_repo(repo_url, clone_dir, timeout=args.timeout)
        if not build_info["cloned"]:
            logging.info("Skipping repo %s due to clone failure", repo_full)
            continue

        pom_found, dep_info = resolve_dependency_version(clone_dir, group_id, artifact_id)
        if not pom_found:
            logging.info("No pom.xml found in %s", repo_full)
            continue

        resolved_version = dep_info.get("resolved_version")
        dependency_source = dep_info.get("source", "unknown")
        version_match = False
        reason = "No resolved version"
        if resolved_version:
            version_match = version_satisfies(resolved_version, version_spec)
            reason = dep_info.get("reason")

        if not version_match:
            logging.info("Version mismatch for %s: %s", repo_full, reason)
            continue

        usage_info = detect_usage(clone_dir, cve_class, cve_method)
        if not usage_info["uses_target_class"] or not usage_info["uses_target_method"]:
            logging.info("Usage not found in %s", repo_full)
            continue

        if not build_info["build_success"]:
            logging.info("Build failed for %s", repo_full)
            continue

        match = {
            "repo": repo_full,
            "repo_url": repo_url,
            "commit": build_info.get("commit"),
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
        result["Matches"].append(match)

    if result["Matches"]:
        result["best_match"] = result["Matches"][0]["repo"]
    else:
        result["reason"] = "No Maven repos found using target dependency version + method call + build success"

    return result


def main():
    parser = argparse.ArgumentParser(description="CVE Maven repo miner")
    parser.add_argument("--input", required=True, help="Input JSON/JSONL file")
    parser.add_argument("--output", required=True, help="Output JSONL file")
    parser.add_argument("--topk", type=int, default=30, help="Max candidate repos per CVE")
    parser.add_argument("--workdir", default=".workdir", help="Working directory for clones")
    parser.add_argument("--timeout", type=int, default=120, help="Build timeout in seconds")
    args = parser.parse_args()

    setup_logger()
    ensure_dir(args.workdir)
    output_path = Path(args.output)
    ensure_dir(str(output_path.parent))

    records = load_vuln_records(args.input)
    mapping = load_mapping()

    searcher = GitHubSearcher(token=os.environ.get("GITHUB_TOKEN"))

    results = []
    for record in records:
        results.append(process_record(record, searcher, mapping, args))

    write_jsonl(args.output, results)
    logging.info("Wrote results to %s", args.output)


if __name__ == "__main__":
    main()
