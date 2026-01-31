"""基础工具函数：日志、目录与 JSONL 输出。"""

import json
import logging
import os
from typing import Iterable


def setup_logger():
    """初始化日志格式与级别。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def ensure_dir(path: str) -> None:
    """确保目录存在。"""
    os.makedirs(path, exist_ok=True)


def write_jsonl(path: str, records: Iterable[dict]) -> None:
    """写入 JSONL 结果文件。"""
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def append_jsonl(path: str, record: dict) -> None:
    """追加单条记录到 JSONL 文件。"""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False))
        handle.write("\n")
