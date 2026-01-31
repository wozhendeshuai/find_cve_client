"""Library 分组工具函数。"""

import logging
from typing import List, Dict, Any


def group_cves_by_library(cve_records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """将 CVE 记录按 CVE_Library 分组。"""
    library_groups = {}
    for record in cve_records:
        library = record.get("CVE_Library", "")
        if not library:
            continue
        
        if library not in library_groups:
            library_groups[library] = []
        library_groups[library].append(record)
    
    logging.info("总共有 %d 个 CVE 记录", len(cve_records))
    logging.info("分组后有 %d 个唯一 Library", len(library_groups))
    
    # 统计信息
    total_cves = sum(len(group) for group in library_groups.values())
    avg_per_library = total_cves / len(library_groups) if library_groups else 0
    logging.info("平均每个 Library 对应 %.1f 个 CVE", avg_per_library)
    
    # 找出最多的 Library
    if library_groups:
        max_library = max(library_groups.items(), key=lambda x: len(x[1]))
        logging.info("最多的 Library: %s (%d 个 CVE)", max_library[0], len(max_library[1]))
    
    return library_groups