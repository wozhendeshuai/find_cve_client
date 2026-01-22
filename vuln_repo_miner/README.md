# Vuln Repo Miner

用于在 GitHub 上自动筛选可复现/可构建的 Java Maven 项目，以匹配 CVE 或 Issue 记录中的依赖版本与类/方法调用。

## 环境要求

- Python 3.9+
- 系统 PATH 中可用 `git` 与 `mvn`（或目标仓库自带 `mvnw`）

安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方式

```bash
export GITHUB_TOKEN=xxxxx
python main.py --input vulns.json --output outputs/result.jsonl --topk 20
```

参数说明：

- `--input` 输入 JSON 数组或 JSONL 文件路径
- `--output` 输出 JSONL 路径
- `--topk` 每条漏洞最多尝试多少候选仓库（默认：30）
- `--workdir` 仓库克隆目录（默认：.workdir）
- `--timeout` 单仓库构建超时时间（默认：120 秒）

## 说明

- 使用 GitHub Search API 并对 rate limit 进行退避处理。
- Maven 依赖版本解析优先做静态 POM 解析，失败后回退到 `mvn dependency:tree`。
- 构建优先使用 `./mvnw -q -DskipTests package`，否则使用 `mvn -q -DskipTests package`。
