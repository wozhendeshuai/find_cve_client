"""输入解析模块：兼容 JSON 数组与 JSONL。"""

import json
import logging


def load_vuln_records(path: str):
    """加载漏洞记录，字段缺失时输出 warning。"""
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read().strip()
        if not content:
            return []
        try:
            if content.startswith("["):
                data = json.loads(content)
                if isinstance(data, list):
                    records = data
                else:
                    logging.warning("Input JSON is not a list")
                    records = [data]
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            logging.error("Failed to parse input: %s", exc)
            return []

    for record in records:
        for key in ["CVE_Number", "CVE_Library", "CVE_Library_version", "CVE_Class", "CVE_Method"]:
            if key not in record:
                logging.warning("Missing field %s in record: %s", key, record.get("CVE_Number", "UNKNOWN"))
    return records
