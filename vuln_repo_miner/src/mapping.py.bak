"""库坐标映射：支持内置映射与 mapping.yml 覆盖。"""

import logging
import os
from typing import Dict, Optional

import yaml

DEFAULT_MAPPING = {
    "commons-codec/commons-codec": {"groupId": "commons-codec", "artifactId": "commons-codec"},
    "org.apache.pdfbox/pdfbox": {"groupId": "org.apache.pdfbox", "artifactId": "pdfbox"},
}


def load_mapping(path: str = "mapping.yml") -> Dict[str, Dict[str, str]]:
    """加载映射表并与默认映射合并。"""
    mapping = DEFAULT_MAPPING.copy()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
                mapping.update(data)
        except Exception as exc:
            logging.warning("Failed to load mapping.yml: %s", exc)
    return mapping


def library_to_maven_coords(library: str, mapping: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    """将 CVE_Library 转为 Maven 坐标。"""
    if library in mapping:
        return mapping[library]
    if "/" in library:
        group_id, artifact_id = library.split("/", 1)
        return {"groupId": group_id, "artifactId": artifact_id}
    logging.warning("Unable to parse library mapping: %s", library)
    return None
