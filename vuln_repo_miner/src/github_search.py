"""GitHub 搜索模块：封装 Search API 与限速退避。"""

import logging
import time
import urllib
from typing import List, Dict, Set

import requests


class GitHubSearcher:
    """GitHub Search API 客户端。"""

    def __init__(self, token: str | None):
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})
        self.session.headers.update({"Accept": "application/vnd.github+json"})

    def _is_fork_or_archived(self, repo: Dict) -> bool:
        """判断仓库是否为 fork 或已归档。"""
        return repo.get("fork", False) or repo.get("archived", False)

    def _get_original_repo(self, repo: Dict) -> Dict:
        """获取原始仓库信息（如果是 fork，则获取父仓库）。"""
        if not repo.get("fork", False):
            return repo

        # 获取父仓库信息
        parent_url = repo.get("parent", {}).get("url")
        if parent_url:
            try:
                response = self.session.get(parent_url, timeout=30)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                logging.warning("Failed to get parent repo info: %s", e)

        return repo

    def _deduplicate_repos(self, repos: List[Dict]) -> List[Dict]:
        """去重仓库列表，优先保留非 fork 仓库。"""
        repo_dict = {}
        original_repos = []

        # 先处理所有仓库，获取原始仓库
        for repo in repos:
            full_name = repo["full_name"].lower()
            if full_name not in repo_dict:
                repo_dict[full_name] = repo

            # 如果是 fork，也记录其父仓库
            if repo.get("fork", False) and "parent" in repo:
                parent = repo["parent"]
                parent_name = parent["full_name"].lower()
                if parent_name not in repo_dict:
                    repo_dict[parent_name] = parent

        # 去重：按 full_name 去重，优先保留非 fork 的
        seen_names: Set[str] = set()
        deduplicated = []

        # 先添加非 fork 仓库
        for repo in repo_dict.values():
            name = repo["full_name"].lower()
            if name not in seen_names and not repo.get("fork", False):
                deduplicated.append(repo)
                seen_names.add(name)

        # 再添加剩余的 fork 仓库（如果还没有该仓库）
        for repo in repo_dict.values():
            name = repo["full_name"].lower()
            if name not in seen_names:
                deduplicated.append(repo)
                seen_names.add(name)

        return deduplicated

    def search_repositories(self, query: str, max_repos: int = None) -> List[dict]:
        """按查询语句返回候选仓库列表，自动处理分页和去重。
        
        Args:
            query: GitHub 搜索查询字符串
            max_repos: 最大仓库数量限制（None 表示不限制，最多1000个）
            
        Returns:
            去重后的仓库列表
        """
        logging.info("GitHub 搜索查询: %s", query)
        results = []
        page = 1
        api_per_page = 100  # GitHub API 最大每页100个结果

        # GitHub Search API 最多返回1000个结果（10页 * 100个）
        max_pages = 10
        if max_repos is not None:
            max_pages = min(max_pages, (max_repos + api_per_page - 1) // api_per_page)

        while page <= max_pages:
            logging.info("Searching page %d", page)
            response = self.session.get(
                f"https://api.github.com/search/code?q={query}&per_page={api_per_page}&page={page}",
                timeout=30
            )

            if response.status_code == 403:
                reset = response.headers.get("X-RateLimit-Reset")
                wait_for = 30
                if reset:
                    wait_for = max(5, int(reset) - int(time.time()))
                logging.warning("Rate limit hit, sleeping %s seconds", wait_for)
                time.sleep(wait_for)
                continue

            if response.status_code != 200:
                logging.error("GitHub search failed: %s", response.text)
                break

            data = response.json()
            items = [item["repository"] for item in data.get("items", []) if "repository" in item]

            if not items:
                break

            results.extend(items)

            # 正确的分页判断：如果返回的结果少于请求的数量，说明是最后一页
            if len(items) < api_per_page:
                break

            page += 1

        # 去重处理
        deduplicated = self._deduplicate_repos(results)

        # 过滤掉已归档的仓库，优先选择活跃仓库
        active_repos = [repo for repo in deduplicated if not repo.get("archived", False)]
        archived_repos = [repo for repo in deduplicated if repo.get("archived", False)]
        final_repos = active_repos + archived_repos

        # 应用最大数量限制（如果指定）
        if max_repos is not None:
            final_repos = final_repos[:max_repos]

        logging.info("Found %d unique repositories after deduplication (from %d total results)",
                     len(final_repos), len(results))
        return final_repos
