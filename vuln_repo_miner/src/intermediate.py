"""中间结果缓存管理模块。"""

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class IntermediateCache:
    """中间结果缓存管理器。"""
    
    def __init__(self, base_dir: str = "intermediate"):
        self.base_dir = Path(base_dir)
        self.search_dir = self.base_dir / "search_results"
        self.clone_dir = self.base_dir / "clone_status"
        self.dependency_dir = self.base_dir / "dependency_analysis"
        self.usage_dir = self.base_dir / "usage_analysis"
        
        # 创建所有必要的目录
        for dir_path in [self.search_dir, self.clone_dir, self.dependency_dir, self.usage_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def get_search_cache_path(self, cve_number: str) -> Path:
        """获取搜索结果缓存路径。"""
        return self.search_dir / f"{cve_number}.json"
    
    def has_search_results(self, cve_number: str) -> bool:
        """检查是否已有搜索结果缓存。"""
        return self.get_search_cache_path(cve_number).exists()
    
    def save_search_results(self, cve_number: str, results: List[Dict]) -> None:
        """保存搜索结果到缓存。"""
        cache_path = self.get_search_cache_path(cve_number)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        logging.info("已保存搜索结果 %s 到 %s", cve_number, cache_path)
    
    def load_search_results(self, cve_number: str) -> Optional[List[Dict]]:
        """从缓存加载搜索结果。"""
        cache_path = self.get_search_cache_path(cve_number)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                results = json.load(f)
            logging.info("已加载缓存的搜索结果，CVE编号: %s", cve_number)
            return results
        except Exception as e:
            logging.warning("加载缓存的搜索结果失败，CVE编号: %s，错误: %s", cve_number, e)
            return None
    
    def get_clone_status_path(self, cve_number: str) -> Path:
        """获取 CVE 克隆状态缓存路径（单个文件包含所有仓库）。"""
        return self.clone_dir / f"{cve_number}.json"
    
    def _load_clone_status_file(self, cve_number: str) -> Dict:
        """加载 CVE 的完整克隆状态文件。"""
        status_path = self.get_clone_status_path(cve_number)
        if not status_path.exists():
            return {}
        
        try:
            with open(status_path, "r", encoding="utf-8") as f:
                status_data = json.load(f)
            return status_data
        except Exception as e:
            logging.warning("加载克隆状态文件失败，CVE编号: %s，错误: %s", cve_number, e)
            return {}
    
    def _save_clone_status_file(self, cve_number: str, status_data: Dict) -> None:
        """保存 CVE 的完整克隆状态文件。"""
        status_path = self.get_clone_status_path(cve_number)
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump(status_data, f, ensure_ascii=False, indent=2)
        logging.debug("已保存克隆状态文件，CVE编号: %s", cve_number)
    
    def load_clone_status(self, cve_number: str, repo_name: str) -> Optional[Dict]:
        """加载特定仓库的克隆状态。"""
        status_data = self._load_clone_status_file(cve_number)
        return status_data.get(repo_name)
    
    def save_clone_status(self, cve_number: str, repo_name: str, status: Dict) -> None:
        """保存特定仓库的克隆状态（追加到 CVE 文件中）。"""
        status_data = self._load_clone_status_file(cve_number)
        status_data[repo_name] = status
        self._save_clone_status_file(cve_number, status_data)
        logging.debug("已保存仓库状态，CVE: %s，仓库: %s", cve_number, repo_name)
    
    def should_process_repo(self, cve_number: str, repo_name: str) -> bool:
        """检查是否应该处理该仓库（未处理过且未删除）。"""
        status = self.load_clone_status(cve_number, repo_name)
        if status is None:
            return True
        # 如果已经处理过（无论成功、失败或删除），都不再处理
        return False
    
    def mark_repo_deleted(self, cve_number: str, repo_name: str, workdir: str, delete_reason: str) -> None:
        """标记仓库为已删除，并实际删除文件。"""
        # 保存删除状态
        status = {
            "status": "deleted",
            "delete_reason": delete_reason,
            "repo_name": repo_name
        }
        self.save_clone_status(cve_number, repo_name, status)
        
        # 实际删除仓库目录
        repo_clone_dir = Path(workdir) / cve_number / repo_name.replace("/", "__")
        if repo_clone_dir.exists():
            try:
                shutil.rmtree(repo_clone_dir)
                logging.info("已删除仓库 %s/%s: %s", cve_number, repo_name, delete_reason)
            except Exception as e:
                logging.warning("删除仓库失败 %s/%s: %s", cve_number, repo_name, e)
    
    def mark_repo_kept(self, cve_number: str, repo_name: str, build_info: Dict, version_match: bool, usage_info: Dict) -> None:
        """标记仓库为保留（满足条件）。"""
        status = {
            "status": "kept",
            "cloned": True,
            "build_success": build_info.get("build_success", False),
            "version_match": version_match,
            "uses_target_class": usage_info.get("uses_target_class", False),
            "uses_target_method": usage_info.get("uses_target_method", False),
            "commit": build_info.get("commit"),
            "build_cmd": build_info.get("build_cmd"),
            "reason": build_info.get("reason", "")
        }
        self.save_clone_status(cve_number, repo_name, status)
    
    def mark_repo_failed(self, cve_number: str, repo_name: str, reason: str) -> None:
        """标记仓库处理失败。"""
        status = {
            "status": "failed", 
            "reason": reason,
            "repo_name": repo_name
        }
        self.save_clone_status(cve_number, repo_name, status)
    
    # Library 级别缓存相关方法
    def get_library_cache_path(self, library_key: str) -> Path:
        """获取 Library 级别缓存路径。"""
        return self.base_dir / "library_cache" / f"{library_key}.json"
    
    def load_library_cache(self, library_key: str) -> Optional[Dict]:
        """加载 Library 级别缓存。"""
        cache_path = self.get_library_cache_path(library_key)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            logging.info("已加载 Library 缓存，Library: %s", library_key)
            return cache_data
        except Exception as e:
            logging.warning("加载 Library 缓存失败，Library: %s，错误: %s", library_key, e)
            return None
    
    def save_library_cache(self, library_key: str, cache_data: Dict) -> None:
        """保存 Library 级别缓存。"""
        cache_path = self.get_library_cache_path(library_key)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
        logging.info("已保存 Library 缓存，Library: %s", library_key)