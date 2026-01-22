"""Maven 解析模块：版本规范解析、依赖解析与候选版本生成。"""

import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests
from packaging.version import Version, InvalidVersion


@dataclass
class VersionSpec:
    """版本规范结构体。"""
    raw: str
    preferred_versions: List[str] = field(default_factory=list)
    constraints: List[Tuple[str, str]] = field(default_factory=list)
    wildcards: List[str] = field(default_factory=list)


def normalize_version(raw: str) -> str:
    """规范化版本字符串（处理 rc/beta/alpha 等）。"""
    cleaned = raw.strip()
    cleaned = cleaned.replace("_", ".")
    cleaned = cleaned.replace(".Beta", "-beta").replace(".beta", "-beta")
    cleaned = cleaned.replace(".Alpha", "-alpha").replace(".alpha", "-alpha")
    cleaned = cleaned.replace(".RC", "-rc").replace(".Rc", "-rc").replace(".rc", "-rc")
    cleaned = cleaned.replace("Beta", "beta").replace("Alpha", "alpha").replace("RC", "rc")
    return cleaned


def parse_version_spec(spec: str) -> VersionSpec:
    """解析版本约束，支持逗号、中文逗号与通配符。"""
    raw = spec or ""
    version_spec = VersionSpec(raw=raw)
    if not raw:
        return version_spec
    parts = re.split(r"[，,]", raw)
    for part in parts:
        token = part.strip()
        if not token:
            continue
        match = re.match(r"(<=|>=|<|>|=)?\s*(.+)", token)
        if not match:
            continue
        op = match.group(1) or "="
        version = match.group(2).strip()
        if version.endswith(".x") or version.endswith(".*"):
            version_spec.wildcards.append(version)
        else:
            version_spec.preferred_versions.append(version)
            version_spec.constraints.append((op, version))
    return version_spec


def _version_key(version: str) -> Version:
    """生成可比较的版本对象。"""
    normalized = normalize_version(version)
    try:
        return Version(normalized)
    except InvalidVersion:
        normalized = re.sub(r"[^0-9A-Za-z.+-]", "", normalized)
        try:
            return Version(normalized)
        except InvalidVersion:
            return Version("0")


def _compare_versions(left: str, right: str) -> int:
    """比较两个版本字符串。"""
    left_v = _version_key(left)
    right_v = _version_key(right)
    if left_v < right_v:
        return -1
    if left_v > right_v:
        return 1
    return 0


def version_satisfies(version: str, spec: VersionSpec) -> bool:
    """判断版本是否满足约束。"""
    if not spec.raw:
        return True
    if not spec.constraints and not spec.wildcards:
        return version in spec.preferred_versions
    for op, constraint_version in spec.constraints:
        cmp_value = _compare_versions(version, constraint_version)
        if op == "<" and not (cmp_value < 0):
            return False
        if op == "<=" and not (cmp_value <= 0):
            return False
        if op == ">" and not (cmp_value > 0):
            return False
        if op == ">=" and not (cmp_value >= 0):
            return False
        if op == "=" and not (cmp_value == 0):
            return False
    for wildcard in spec.wildcards:
        prefix = wildcard.replace(".x", ".").replace(".*", ".")
        if not version.startswith(prefix):
            return False
    return True


def fetch_maven_versions(group_id: str, artifact_id: str) -> List[str]:
    """从 Maven Central 拉取版本列表。"""
    query = f'g:"{group_id}" AND a:"{artifact_id}"'
    url = "https://search.maven.org/solrsearch/select"
    params = {
        "q": query,
        "rows": 200,
        "core": "gav",
    }
    response = requests.get(url, params=params, timeout=30)
    response.raise_for_status()
    data = response.json()
    versions = [doc["v"] for doc in data.get("response", {}).get("docs", [])]
    return versions


def generate_candidate_versions(group_id: str, artifact_id: str, spec: VersionSpec) -> List[str]:
    """生成候选版本列表，失败时降级为 preferred_versions。"""
    candidates = list(spec.preferred_versions)
    needs_query = bool(spec.wildcards or spec.constraints)
    if needs_query:
        try:
            versions = fetch_maven_versions(group_id, artifact_id)
            filtered = [v for v in versions if version_satisfies(v, spec)]
            candidates.extend(filtered)
        except Exception as exc:
            logging.warning("Failed to query Maven Central: %s", exc)
    unique = list(dict.fromkeys(candidates))
    return unique


def _extract_text(elem: Optional[ET.Element]) -> Optional[str]:
    """提取 XML 文本内容。"""
    if elem is None or elem.text is None:
        return None
    return elem.text.strip()


def _parse_pom(pom_path: str) -> Dict[str, Dict[str, str]]:
    """解析单个 pom.xml，收集 properties 与 dependencyManagement。"""
    tree = ET.parse(pom_path)
    root = tree.getroot()
    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = ns_match.group(1) if ns_match else ""
    nsmap = {"m": ns} if ns else {}

    def find(path):
        return root.find(path, nsmap)

    def findall(path):
        return root.findall(path, nsmap)

    properties = {}
    props = find("m:properties")
    if props is not None:
        for child in list(props):
            key = child.tag.split("}")[-1]
            value = child.text.strip() if child.text else ""
            properties[key] = value

    dep_mgmt = {}
    dep_mgmt_node = find("m:dependencyManagement/m:dependencies")
    if dep_mgmt_node is not None:
        for dep in dep_mgmt_node.findall("m:dependency", nsmap):
            gid = _extract_text(dep.find("m:groupId", nsmap))
            aid = _extract_text(dep.find("m:artifactId", nsmap))
            ver = _extract_text(dep.find("m:version", nsmap))
            if gid and aid and ver:
                dep_mgmt[f"{gid}:{aid}"] = ver

    dependencies = []
    deps_node = find("m:dependencies")
    if deps_node is not None:
        for dep in deps_node.findall("m:dependency", nsmap):
            gid = _extract_text(dep.find("m:groupId", nsmap))
            aid = _extract_text(dep.find("m:artifactId", nsmap))
            ver = _extract_text(dep.find("m:version", nsmap))
            dependencies.append({"groupId": gid, "artifactId": aid, "version": ver})

    parent = {}
    parent_node = find("m:parent")
    if parent_node is not None:
        parent["groupId"] = _extract_text(parent_node.find("m:groupId", nsmap))
        parent["artifactId"] = _extract_text(parent_node.find("m:artifactId", nsmap))
        parent["version"] = _extract_text(parent_node.find("m:version", nsmap))
        parent["relativePath"] = _extract_text(parent_node.find("m:relativePath", nsmap))

    return {
        "properties": properties,
        "dependencyManagement": dep_mgmt,
        "dependencies": dependencies,
        "parent": parent,
    }


def _resolve_property(value: Optional[str], properties: Dict[str, str]) -> Optional[str]:
    """解析 ${xxx} 形式的 POM 属性引用。"""
    if not value:
        return value
    match = re.match(r"\$\{([^}]+)\}", value)
    if match:
        key = match.group(1)
        return properties.get(key, value)
    return value


def _collect_poms(repo_path: str) -> List[str]:
    """收集仓库中的所有 pom.xml。"""
    pom_files = []
    for root, _, files in os.walk(repo_path):
        for name in files:
            if name == "pom.xml":
                pom_files.append(os.path.join(root, name))
    return pom_files


def resolve_dependency_version(repo_path: str, group_id: str, artifact_id: str) -> Tuple[bool, Dict[str, str]]:
    """解析依赖版本，静态解析失败时回退到 mvn dependency:tree。"""
    pom_files = _collect_poms(repo_path)
    if not pom_files:
        return False, {}

    combined_properties: Dict[str, str] = {}
    combined_dep_mgmt: Dict[str, str] = {}

    for pom in pom_files:
        try:
            parsed = _parse_pom(pom)
            combined_properties.update(parsed["properties"])
            combined_dep_mgmt.update(parsed["dependencyManagement"])
        except Exception as exc:
            logging.warning("Failed to parse %s: %s", pom, exc)

    target_key = f"{group_id}:{artifact_id}"

    for pom in pom_files:
        try:
            parsed = _parse_pom(pom)
        except Exception:
            continue
        for dep in parsed["dependencies"]:
            if dep["groupId"] == group_id and dep["artifactId"] == artifact_id:
                version = dep.get("version")
                source = "pom_direct"
                resolved = _resolve_property(version, combined_properties)
                if resolved and resolved != version:
                    source = "pom_property"
                if not resolved:
                    resolved = combined_dep_mgmt.get(target_key)
                    if resolved:
                        source = "dependencyManagement"
                if resolved:
                    return True, {
                        "resolved_version": resolved,
                        "source": source,
                        "reason": f"Resolved via {source}",
                    }

    # fallback to dependencyManagement only
    if target_key in combined_dep_mgmt:
        return True, {
            "resolved_version": combined_dep_mgmt[target_key],
            "source": "dependencyManagement",
            "reason": "Resolved via dependencyManagement",
        }

    # dynamic fallback
    mvn_output = _run_dependency_tree(repo_path, group_id, artifact_id)
    if mvn_output:
        match = re.search(rf"{re.escape(group_id)}:{re.escape(artifact_id)}:[^:]+:([^:]+):", mvn_output)
        if match:
            return True, {
                "resolved_version": match.group(1),
                "source": "mvn_dependency_tree",
                "reason": "Resolved via mvn dependency:tree",
            }

    return True, {
        "resolved_version": None,
        "source": "unknown",
        "reason": "Unable to resolve dependency version",
    }


def _run_dependency_tree(repo_path: str, group_id: str, artifact_id: str) -> Optional[str]:
    """执行 mvn dependency:tree 并返回输出。"""
    cmd = ["mvn", "-q", "-DskipTests", "dependency:tree", f"-Dincludes={group_id}:{artifact_id}"]
    try:
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=120)
    except Exception as exc:
        logging.warning("Failed to run mvn dependency:tree: %s", exc)
        return None
    if result.returncode != 0:
        logging.warning("mvn dependency:tree failed: %s", result.stderr[-200:])
        return None
    return result.stdout
