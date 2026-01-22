"""GitHub 搜索模块：封装 Search API 与限速退避。"""

import logging
import time
from typing import List

import requests


class GitHubSearcher:
    """GitHub Search API 客户端。"""
    def __init__(self, token: str | None):
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"token {token}"})
        self.session.headers.update({"Accept": "application/vnd.github+json"})

    def search_repositories(self, query: str, max_repos: int = 30) -> List[dict]:
        """按查询语句返回候选仓库列表。"""
        logging.info("GitHub search query: %s", query)
        results = []
        page = 1
        per_page = 30
        while len(results) < max_repos:
            params = {"q": query, "per_page": per_page, "page": page}
            response = self.session.get("https://api.github.com/search/repositories", params=params, timeout=30)
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
            items = data.get("items", [])
            results.extend(items)
            if len(items) < per_page:
                break
            page += 1
        return results[:max_repos]
