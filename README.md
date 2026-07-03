# Vuln Scan Tool

面向 Linux network namespace 的资产扫描和漏洞验证工具。输入一个 namespace 和一组 IP，工具先用 fscan SDK 做端口、服务、Web 指纹识别，再把目标交给 nuclei SDK 做漏洞模板验证。

适合的使用环境：

- 云平台、容器平台、虚拟化平台中，每个租户或网络隔离域对应一个 Linux network namespace。
- 运维侧已经拿到某个 namespace 下的一批内网 IP，需要快速识别资产和做定向漏洞验证。
- 希望以 CLI 临时扫描，或以 HTTP 服务方式接收扫描任务并持久化结果。

扫描流程：

```text
namespace + IP 列表
  -> ip netns exec 进入目标网络命名空间
  -> fscan SDK 识别端口、服务、Web 信息
  -> 轻量 HTTP 指纹补充
  -> 可选 poc_map 按指纹缩小 nuclei 模板范围
  -> nuclei SDK 执行漏洞验证
  -> 输出 JSON 或写入 SQLite
```

目录：

- [CLI 最小使用](#cli-最小使用)
- [HTTP 服务最小部署](#http-服务最小部署)
- [输出格式](#输出格式)
- [参数和环境变量](#参数和环境变量)
- [POC 模板仓库](#poc-模板仓库)
- [poc_map.json](#poc_mapjson)
- [构建](#构建)
- [排查](#排查)

## CLI 最小使用

准备二进制：

```bash
VERSION=v0.1.0
BASE_URL=https://github.com/systemime/fast_scan_tool/releases/download/${VERSION}

case "$(uname -m)" in
  x86_64) ASSET=vulnscan-wrapper-linux-amd64 ;;
  aarch64|arm64) ASSET=vulnscan-wrapper-linux-arm64 ;;
  armv7l|armv7*) ASSET=vulnscan-wrapper-linux-armv7 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

curl -L -o /tmp/vulnscan-wrapper "${BASE_URL}/${ASSET}"
chmod +x /tmp/vulnscan-wrapper
```

准备 nuclei 模板：

```bash
sudo git clone https://github.com/adysec/nuclei_poc.git /opt/nuclei_poc
```

最小扫描命令：

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
/tmp/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -out scan-result.json
```

这条命令表示：在 `ns1` 这个 network namespace 内扫描 `10.0.0.1` 和 `10.0.0.2`，nuclei 模板从 `/opt/nuclei_poc/poc_high_quality` 加载，结果写入 `scan-result.json`。

CLI 模式不启动 HTTP 服务，不写 SQLite。单个 IP 扫描失败时，错误会写到该 host 的 `error` 字段。

查看帮助：

```bash
/tmp/vulnscan-wrapper --help
/tmp/vulnscan-wrapper scan -h
```

## HTTP 服务最小部署

安装二进制：

```bash
sudo install -d -m 0755 /opt/vulnscan /etc/vulnscan /var/lib/vulnscan /var/log/vulnscan
sudo install -m 0755 /tmp/vulnscan-wrapper /opt/vulnscan/vulnscan-wrapper
```

准备环境文件：

```bash
sudo tee /etc/vulnscan/vulnscan.env >/dev/null <<'EOF'
VST_ADDR=127.0.0.1:8080
VST_DB=/var/lib/vulnscan/tasks.db
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality
VST_WORKERS=6
EOF
```

创建 systemd 服务：

```bash
sudo tee /etc/systemd/system/vulnscan-wrapper.service >/dev/null <<'EOF'
[Unit]
Description=Vuln Scan Tool
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vulnscan
EnvironmentFile=/etc/vulnscan/vulnscan.env
ExecStart=/opt/vulnscan/vulnscan-wrapper
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-wrapper
```

最小 API 调用：

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"ns1","ip_hosts":["10.0.0.1","10.0.0.2"],"timeout":600}'
```

查询结果：

```bash
curl -sS http://127.0.0.1:8080/scan/ns1
curl -sS 'http://127.0.0.1:8080/scan?namespace=ns1'
```

批量提交多个 namespace：

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '[{"namespace":"ns1","ip_hosts":["10.0.0.1"],"timeout":600},{"namespace":"ns2","ip_hosts":["10.0.1.1"],"timeout":600}]'
```

HTTP API 只允许本机访问。远程调用用 SSH tunnel：

```bash
ssh -L 8080:127.0.0.1:8080 root@target-server
```

## 输出格式

CLI 扫描结果写入 `-out` 指定的 JSON 文件：

```json
{
  "namespace": "ns1",
  "hosts": [
    {
      "ip": "10.0.0.1",
      "assets": [
        {
          "type": "service",
          "target": "10.0.0.1:80",
          "port": 80,
          "service": "http",
          "url": "http://10.0.0.1:80",
          "title": "Example",
          "server": "nginx",
          "status_code": 200,
          "is_web": true
        }
      ],
      "vulnerabilities": 1,
      "vulnerability_ids": ["CVE-2024-0001"]
    },
    {
      "ip": "10.0.0.2",
      "assets": [],
      "vulnerabilities": 0,
      "vulnerability_ids": [],
      "error": "context deadline exceeded"
    }
  ]
}
```

HTTP 提交任务返回新增和移除的 host。提交单个 namespace 返回对象，批量提交返回对象数组：

```json
{
  "namespace": "ns1",
  "host_count": 2,
  "timeout": 600,
  "added": ["10.0.0.1", "10.0.0.2"],
  "removed": []
}
```

HTTP 查询结果从 SQLite 读取，host 状态为 `pending`、`running`、`completed` 或 `timeout`：

```json
{
  "namespace": "ns1",
  "host_count": 2,
  "timeout": 600,
  "hosts": [
    {
      "ip": "10.0.0.1",
      "status": "completed",
      "timeout": 600,
      "assets": [],
      "vulnerabilities": 0,
      "vulnerability_ids": [],
      "started_at": "2026-07-03T10:00:00Z",
      "finished_at": "2026-07-03T10:02:00Z"
    }
  ]
}
```

HTTP 错误统一返回：

```json
{"error":"namespace not found"}
```

## 参数和环境变量

CLI 参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-namespace` | 空 | Linux network namespace 名称，必填 |
| `-ips` | 空 | 逗号分隔的 IP/host 列表，必填 |
| `-out` | `scan-result.json` | JSON 输出文件 |
| `-timeout` | `600` | 单 host 超时，秒 |
| `-workers` | `6` | CLI 模式下同时扫描的 host 数 |
| `-total-timeout` | `1800` | CLI 总超时，秒；设为 `0` 关闭 |

HTTP 请求字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `namespace` | string | Linux network namespace 名称 |
| `ip_hosts` | string array | 要扫描的 IP/host，会去重并排序；不能为空 |
| `timeout` | int | 单 host 超时，秒；小于等于 0 时使用 `600` |

环境变量和 JSON 配置字段：

| 环境变量 | JSON 字段 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `VST_CONFIG` / `CONFIG` | - | 空 | JSON 配置文件路径；环境变量优先 |
| `VST_ADDR` / `ADDR` | `addr` | `127.0.0.1:8080` | HTTP 监听地址 |
| `VST_DB` / `DB_PATH` | `db_path` | `tasks.db` | SQLite 数据库路径 |
| `VST_POC_DIR` / `POC_DIR` | `poc_dir` | 程序同级 `poc` | nuclei 模板目录 |
| `VST_POC_MAP` / `POC_MAP` | `poc_map` | 空 | 可选，资产指纹到模板路径的映射 |
| `VST_FSCAN_PATH` / `FSCAN_PATH` | `fscan_path` | `fscan` | 兼容旧配置；SDK 路径不调用外部二进制 |
| `VST_FSCAN_THREADS` / `FSCAN_THREADS` | `fscan_threads` | `256` | fscan SDK 并发线程 |
| `VST_FSCAN_TIMEOUT` / `FSCAN_TIMEOUT` | `fscan_timeout` | `3` | fscan 单探测超时，秒 |
| `VST_FSCAN_PORTS` / `FSCAN_PORTS` | `fscan_ports` | fscan 默认端口 | 逗号分隔端口列表 |
| `VST_WORKERS` / `WORKERS` | `workers` | `CPU * 1.5` 向上取整 | HTTP 服务模式下 host 并发 |
| `VST_NUCLEI_CONCURRENCY` / `NUCLEI_CONCURRENCY` | `nuclei_concurrency` | `25` | 单 host 内 nuclei 模板并发 |
| `VST_NUCLEI_HOST_CONCURRENCY` / `NUCLEI_HOST_CONCURRENCY` | `nuclei_host_concurrency` | `1` | 单 host 内 nuclei target 并发 |
| `VST_NUCLEI_TIMEOUT` / `NUCLEI_TIMEOUT` | `nuclei_timeout` | `5` | nuclei 单请求/连接超时，秒 |
| `VST_HTTP_FINGERPRINT_TIMEOUT` / `HTTP_FINGERPRINT_TIMEOUT` | `http_fingerprint_timeout` | `2` | fscan 后追加 HTTP 指纹超时，秒；设为 `0` 关闭 |

示例 JSON 配置：

```json
{
  "addr": "127.0.0.1:8080",
  "db_path": "/var/lib/vulnscan/tasks.db",
  "poc_dir": "/opt/nuclei_poc/poc_high_quality",
  "poc_map": "/etc/vulnscan/poc-map.json",
  "fscan_path": "fscan",
  "workers": 6,
  "fscan_threads": 256,
  "fscan_timeout": 3,
  "fscan_ports": [80, 443, 8080, 8443, 22, 3306, 5432, 6379],
  "nuclei_concurrency": 50,
  "nuclei_host_concurrency": 10,
  "nuclei_timeout": 2,
  "http_fingerprint_timeout": 2
}
```

## POC 模板仓库

推荐使用：

```bash
sudo git clone https://github.com/adysec/nuclei_poc.git /opt/nuclei_poc
```

常用目录：

```text
/opt/nuclei_poc/poc_high_quality
/opt/nuclei_poc/poc_all
```

`poc_high_quality` 模板数量更少，适合控制扫描时长；`poc_all` 更全，但耗时更长。

也可以使用官方模板仓库：

```bash
sudo git clone https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates
```

此时设置：

```bash
VST_POC_DIR=/opt/nuclei-templates
```

只要目录下是 nuclei 支持的 `.yaml` / `.yml` 模板，就可以直接作为 `VST_POC_DIR` 使用，不需要转换。

## poc_map.json

`poc_map.json` 不是 POC 仓库。它是可选加速文件，用资产指纹命中模板目录，减少 nuclei 实际加载的模板数量。

格式：

```json
{
  "http": ["http/"],
  "https": ["http/"],
  "port:80": ["http/"],
  "port:443": ["http/"],
  "nginx": ["nginx/"],
  "tomcat": ["tomcat/"],
  "jenkins": ["jenkins/"],
  "redis": ["redis/"],
  "_baseline": ["http/"]
}
```

规则：

- key 是指纹关键词，会和 fscan/HTTP 识别出的 `service`、`protocol`、`server`、`title`、`banner`、`fingerprints`、`port:<端口>` 做包含匹配。
- value 是 `VST_POC_DIR` 下的相对目录或模板文件。
- 未配置、读取失败或解析失败 `poc_map` 时，直接加载整个 `VST_POC_DIR`。
- 配置了 `poc_map` 且命中指纹时，只加载命中路径和 `_baseline` / `baseline`。
- 配置了 `poc_map` 但未命中指纹时，只加载 `_fallback` / `fallback` / `_baseline` / `baseline`；这些也没有时跳过 nuclei。
- value 越出 `VST_POC_DIR` 会被忽略。

从 `nuclei_poc` 自动生成 `poc_map.json`：

```bash
POC_DIR=/opt/nuclei_poc/poc_high_quality
OUT=/etc/vulnscan/poc-map.json

sudo install -d -m 0755 "$(dirname "$OUT")"

POC_DIR="$POC_DIR" OUT=/tmp/poc-map.json python3 - <<'PY'
import json
import os
import re
from pathlib import Path

poc_dir = Path(os.environ["POC_DIR"]).resolve()
out = Path(os.environ["OUT"])

keywords = [
    "http", "https", "nginx", "apache", "iis", "tomcat", "jenkins",
    "weblogic", "nacos", "spring", "thinkphp", "wordpress", "gitlab",
    "grafana", "prometheus", "kibana", "elasticsearch", "elastic",
    "redis", "mysql", "postgres", "mongodb", "minio", "harbor",
    "ssh", "ftp", "smb", "rdp",
]

mapping = {}

def add(key, rel):
    mapping.setdefault(key, set()).add(rel)

for path in poc_dir.rglob("*"):
    if path.suffix.lower() not in {".yaml", ".yml"}:
        continue
    rel = path.relative_to(poc_dir).as_posix()
    text = rel.lower()
    tokens = set(re.split(r"[^a-z0-9]+", text))

    for key in keywords:
        if key in text or key in tokens:
            parent = path.parent.relative_to(poc_dir).as_posix()
            add(key, parent + "/" if parent != "." else rel)

for key in ("http", "https", "port:80", "port:443"):
    for candidate in ("http/", "web/", "network/"):
        if (poc_dir / candidate).exists():
            add(key, candidate)

common_ports = {
    "ssh": ["port:22"],
    "ftp": ["port:21"],
    "smb": ["port:445"],
    "rdp": ["port:3389"],
    "redis": ["port:6379"],
    "mysql": ["port:3306"],
    "postgres": ["port:5432"],
    "mongodb": ["port:27017"],
    "elasticsearch": ["port:9200", "port:9300"],
}
for service, ports in common_ports.items():
    for value in mapping.get(service, set()):
        for port in ports:
            add(port, value)

if "http" in mapping:
    mapping["_baseline"] = set(mapping["http"])
serializable = {key: sorted(values) for key, values in sorted(mapping.items())}
out.write_text(json.dumps(serializable, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"wrote {out} with {len(serializable)} keys")
PY

sudo install -m 0644 /tmp/poc-map.json "$OUT"
```

校验生成结果：

```bash
POC_DIR=/opt/nuclei_poc/poc_high_quality
OUT=/etc/vulnscan/poc-map.json

POC_DIR="$POC_DIR" OUT="$OUT" python3 - <<'PY'
import json
import os
from pathlib import Path

poc_dir = Path(os.environ["POC_DIR"]).resolve()
mapping = json.load(open(os.environ["OUT"], encoding="utf-8"))

errors = []
for key, values in mapping.items():
    if not isinstance(values, list):
        errors.append(f"{key}: value must be list")
        continue
    for value in values:
        path = (poc_dir / value).resolve()
        if poc_dir not in (path, *path.parents):
            errors.append(f"{key}: out of poc_dir: {value}")
        elif not path.exists():
            errors.append(f"{key}: missing: {value}")

if errors:
    print("\n".join(errors))
    raise SystemExit(1)

print("poc-map ok")
PY
```

自动生成的 map 只是按路径关键词归类，适合作为起点。上线前看日志里的 `templates_selected`、`poc_map_hit_rate`，再删掉误命中的 key 或补充业务常见组件。

使用 map：

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_POC_MAP=/etc/vulnscan/poc-map.json \
/tmp/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1 \
  -out scan-result.json
```

## 构建

源码布局：

```text
/opt/project/
  fast_scan_tool/
  fscan/
```

`go.mod` 使用本地 replace：

```text
replace github.com/shadow1ng/fscan => ../fscan
```

本地构建：

```bash
go build -trimpath -o vulnscan-wrapper .
```

交叉编译：

```bash
mkdir -p dist

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-amd64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-arm64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-armv7 .

sha256sum dist/vulnscan-wrapper-linux-* poc-map-budget.example.json > dist/SHA256SUMS
```

SQLite 使用纯 Go 驱动 `modernc.org/sqlite`，不需要 CGO 或系统 sqlite 开发库。

## 排查

日志里关注这一行：

```text
nuclei templates_total=34840 templates_selected=111 template_reduction_ratio=99.7% poc_map_hit_rate=100.0% poc_map_assets_matched=4/4 fallback_full_scan=false skip_nuclei=false fingerprint_hits=http,port:80
```

字段含义：

| 字段 | 说明 |
| --- | --- |
| `templates_total` | `VST_POC_DIR` 下模板总数 |
| `templates_selected` | 本次实际加载的模板数 |
| `poc_map_hit_rate` | 资产命中 `poc_map` 的比例 |
| `fallback_full_scan=true` | 没有可用 map，回退全量模板 |
| `skip_nuclei=true` | 配了 map 但未命中且没有 fallback/baseline |

资源抖动时先降 `VST_WORKERS`，再降 `VST_NUCLEI_CONCURRENCY`。排查目标 `9100` 端口时，用目标 namespace 和目标 IP：

```bash
ip netns exec <namespace> curl http://<目标IP>:9100/metrics
```
