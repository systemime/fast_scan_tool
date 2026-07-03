# Vuln Scan Tool

面向 Linux network namespace 的资产扫描和漏洞验证工具。

扫描链路：

```text
namespace + IP 列表
  -> fscan SDK 资产识别
  -> 轻量 HTTP 指纹补充
  -> 可选 poc_map 收敛 nuclei 模板
  -> nuclei SDK 漏洞验证
  -> JSON / SQLite 结果
```

CLI 模式适合一次性扫描一个 namespace 下的多个 IP。HTTP 服务模式适合接收任务、持久化状态并持续调度。

## 快速安装

Release 提供 Linux 静态二进制，目标机器不需要安装 Go。

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

sudo install -d -m 0755 /opt/vulnscan /etc/vulnscan /var/lib/vulnscan /var/log/vulnscan
sudo install -m 0755 /tmp/vulnscan-wrapper /opt/vulnscan/vulnscan-wrapper

/opt/vulnscan/vulnscan-wrapper --help
```

二进制不包含 nuclei 模板。准备模板目录后再扫描，例如：

```bash
sudo git clone <poc_repo_url> /opt/nuclei_poc/poc_high_quality
```

如果模板目录不是 `/opt/nuclei_poc/poc_high_quality`，同步修改 `VST_POC_DIR`。配置了 `poc_map` 时，再同步 map 里的相对路径。

## CLI 扫描

只指定 `VST_POC_DIR` 时，nuclei 会直接加载该目录下的模板；不需要把 POC 仓库转换成 JSON。

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_NUCLEI_CONCURRENCY=50 \
VST_NUCLEI_HOST_CONCURRENCY=10 \
VST_NUCLEI_TIMEOUT=2 \
/opt/vulnscan/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -timeout 600 \
  -workers 6 \
  -total-timeout 1800 \
  -out scan-result.json
```

这段命令的含义：

| 配置/参数 | 含义 |
| --- | --- |
| `VST_POC_DIR=/opt/nuclei_poc/poc_high_quality` | nuclei 模板目录 |
| `VST_NUCLEI_CONCURRENCY=50` | 单个 host 内 nuclei 模板并发数 |
| `VST_NUCLEI_HOST_CONCURRENCY=10` | 单个 host 内 nuclei target 并发数 |
| `VST_NUCLEI_TIMEOUT=2` | nuclei 单次请求/连接超时，单位秒 |
| `/opt/vulnscan/vulnscan-wrapper scan` | 启动一次 CLI 扫描 |
| `-namespace ns1` | 在 `ns1` 这个 Linux network namespace 内扫描 |
| `-ips 10.0.0.1,10.0.0.2` | 本次扫描的目标 IP 列表 |
| `-timeout 600` | 每个 IP 最多扫描 600 秒 |
| `-workers 6` | 同时扫描 6 个 IP |
| `-total-timeout 1800` | 本次 CLI 扫描总预算 1800 秒 |
| `-out scan-result.json` | 扫描结果写入 `scan-result.json` |

CLI 模式不启动 HTTP 服务，也不写 SQLite。每个 host 都会写入 JSON；失败原因在对应 host 的 `error` 字段里。

需要减少模板加载量时，再加 `VST_POC_MAP`：

```bash
VERSION=v0.1.0
BASE_URL=https://github.com/systemime/fast_scan_tool/releases/download/${VERSION}

curl -L -o /tmp/poc-map-budget.example.json "${BASE_URL}/poc-map-budget.example.json"
sudo install -m 0644 /tmp/poc-map-budget.example.json /etc/vulnscan/poc-map.json

VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_POC_MAP=/etc/vulnscan/poc-map.json \
/opt/vulnscan/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -out scan-result.json
```

`VST_POC_MAP` 不是第二个 POC 仓库。它只是“资产指纹 -> `VST_POC_DIR` 下的相对路径”映射，用来少跑模板。map 路径不匹配当前模板仓库时，不要配置它，直接扫 `VST_POC_DIR` 更稳。

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-namespace` | Linux network namespace 名称 |
| `-ips` | 逗号分隔的 IP/host 列表 |
| `-timeout` | 单 host 超时，秒，默认 `600` |
| `-workers` | host 并发数，默认 `6` |
| `-total-timeout` | 整体超时，秒，默认 `1800`，设为 `0` 关闭 |
| `-out` | JSON 输出文件，默认 `scan-result.json` |

查看帮助：

```bash
/opt/vulnscan/vulnscan-wrapper --help
/opt/vulnscan/vulnscan-wrapper scan -h
```

## HTTP 服务

服务模式会监听本地 API、写 SQLite，并由 worker 池调度扫描。进入 network namespace 通常需要 root 权限。

创建环境文件：

```bash
sudo tee /etc/vulnscan/vulnscan.env >/dev/null <<'EOF'
VST_ADDR=127.0.0.1:8080
VST_DB=/var/lib/vulnscan/tasks.db
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality
VST_WORKERS=6
VST_FSCAN_THREADS=256
VST_FSCAN_TIMEOUT=3
VST_NUCLEI_CONCURRENCY=50
VST_NUCLEI_HOST_CONCURRENCY=10
VST_NUCLEI_TIMEOUT=2
VST_HTTP_FINGERPRINT_TIMEOUT=2
EOF
```

创建 systemd 服务：

```bash
sudo tee /etc/systemd/system/vulnscan-wrapper.service >/dev/null <<'EOF'
[Unit]
Description=Vuln Scan Tool
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vulnscan
EnvironmentFile=/etc/vulnscan/vulnscan.env
ExecStart=/opt/vulnscan/vulnscan-wrapper
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StandardOutput=append:/var/log/vulnscan/vulnscan-wrapper.log
StandardError=append:/var/log/vulnscan/vulnscan-wrapper.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-wrapper
sudo systemctl status vulnscan-wrapper --no-pager
```

老版本 systemd 不支持 `StandardOutput=append:` 时，删除 `StandardOutput` 和 `StandardError` 两行，改用 journald：

```bash
journalctl -u vulnscan-wrapper -f
```

## API

API 只允许 loopback 地址访问，非本机请求返回 `403`。远程调用用 SSH tunnel：

```bash
ssh -L 8080:127.0.0.1:8080 root@target-server
```

提交单组任务：

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"ns1","ip_hosts":["10.0.0.1","10.0.0.2"],"timeout":600}'
```

提交多组任务：

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '[{"namespace":"ns1","ip_hosts":["10.0.0.1","10.0.0.2"],"timeout":600},{"namespace":"ns2","ip_hosts":["10.0.1.1"],"timeout":600}]'
```

查询结果：

```bash
curl -sS http://127.0.0.1:8080/scan/ns1
curl -sS 'http://127.0.0.1:8080/scan?namespace=ns1'
```

请求字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `namespace` | string | Linux network namespace 名称 |
| `ip_hosts` | string array | 要扫描的 IP/host，会去重并排序；不能为空 |
| `timeout` | int | 单 host 超时，秒；小于等于 0 时使用 `600` |

## 配置

配置可来自 JSON 文件，也可来自环境变量。环境变量优先。通过 `VST_CONFIG` 或 `CONFIG` 指定 JSON 文件。

```json
{
  "addr": "127.0.0.1:8080",
  "db_path": "/var/lib/vulnscan/tasks.db",
  "poc_dir": "/opt/nuclei_poc/poc_high_quality",
  "poc_map": "",
  "workers": 6,
  "nuclei_concurrency": 50,
  "nuclei_host_concurrency": 10,
  "nuclei_timeout": 2,
  "http_fingerprint_timeout": 2,
  "fscan_threads": 256,
  "fscan_timeout": 3,
  "fscan_ports": [80, 443, 8080, 8443, 22, 3306, 5432, 6379, 2379, 2380]
}
```

| 环境变量 | 配置字段 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `VST_CONFIG` / `CONFIG` | - | 空 | JSON 配置文件路径 |
| `VST_ADDR` / `ADDR` | `addr` | `127.0.0.1:8080` | HTTP 监听地址 |
| `VST_DB` / `DB_PATH` | `db_path` | `tasks.db` | SQLite 数据库路径 |
| `VST_POC_DIR` / `POC_DIR` | `poc_dir` | 程序同级 `poc` | nuclei 模板目录 |
| `VST_POC_MAP` / `POC_MAP` | `poc_map` | 空 | 资产指纹到 POC 路径映射 |
| `VST_FSCAN_PATH` / `FSCAN_PATH` | `fscan_path` | `fscan` | 兼容旧配置；SDK 路径不调用外部二进制 |
| `VST_FSCAN_THREADS` / `FSCAN_THREADS` | `fscan_threads` | `256` | fscan SDK 并发线程 |
| `VST_FSCAN_TIMEOUT` / `FSCAN_TIMEOUT` | `fscan_timeout` | `3` | fscan 单探测超时，秒 |
| `VST_FSCAN_PORTS` / `FSCAN_PORTS` | `fscan_ports` | fscan 默认端口 | 逗号分隔端口列表 |
| `VST_WORKERS` / `WORKERS` | `workers` | `CPU * 1.5` 向上取整 | 服务模式下 host 并发 |
| `VST_NUCLEI_CONCURRENCY` / `NUCLEI_CONCURRENCY` | `nuclei_concurrency` | `25` | 单 host 内 nuclei 模板并发 |
| `VST_NUCLEI_HOST_CONCURRENCY` / `NUCLEI_HOST_CONCURRENCY` | `nuclei_host_concurrency` | `1` | 单 host 内 nuclei target 并发 |
| `VST_NUCLEI_TIMEOUT` / `NUCLEI_TIMEOUT` | `nuclei_timeout` | `5` | nuclei 单请求/连接超时，秒 |
| `VST_HTTP_FINGERPRINT_TIMEOUT` / `HTTP_FINGERPRINT_TIMEOUT` | `http_fingerprint_timeout` | `2` | fscan 后追加 HTTP 指纹超时，秒；设为 `0` 关闭 |

`fscan_path` 只保留兼容旧配置。

## POC Map

`poc_map` 是可选 JSON 文件。key 是资产指纹关键词，value 是 `poc_dir` 下的目录或模板文件。

```json
{
  "http": ["http/"],
  "https": ["http/"],
  "port:80": ["http/"],
  "port:443": ["http/"],
  "ssh": ["ssh/"],
  "openssh": ["ssh/"],
  "port:22": ["ssh/"],
  "redis": ["redis/"],
  "mysql": ["mysql/"],
  "mongodb": ["mongodb/"],
  "elastic": ["elk/elasticsearch_1.yaml"],
  "_baseline": ["http/"]
}
```

构建方式：

1. 先确定 nuclei 模板根目录：

```bash
POC_DIR=/opt/nuclei_poc/poc_high_quality
find "$POC_DIR" -maxdepth 2 -type d | sed "s#^$POC_DIR/##" | sort | head -80
```

2. 按实际目录写 map。key 用 fscan/HTTP 指纹里可能出现的关键词，例如 `http`、`nginx`、`tomcat`、`jenkins`、`redis`、`port:80`。value 必须是 `POC_DIR` 下的相对路径：

```bash
sudo tee /etc/vulnscan/poc-map.json >/dev/null <<'EOF'
{
  "http": ["http/"],
  "https": ["http/"],
  "port:80": ["http/"],
  "port:443": ["http/"],
  "nginx": ["nginx/"],
  "tomcat": ["tomcat/"],
  "jenkins": ["jenkins/"],
  "redis": ["redis/"],
  "mysql": ["mysql/"],
  "_baseline": ["http/"]
}
EOF
```

上面的 value 只是示例。模板仓库里没有对应目录时，要改成真实存在的目录或 YAML 文件。仓库自带的 `poc-map-budget.example.json` 可以直接作为 `/opt/nuclei_poc/poc_high_quality` 结构的起点。

3. 校验 map 里的路径：

```bash
POC_DIR=/opt/nuclei_poc/poc_high_quality
MAP=/etc/vulnscan/poc-map.json

python3 - <<'PY'
import json
import os
import sys

poc_dir = os.path.abspath(os.environ["POC_DIR"])
map_path = os.environ["MAP"]
mapping = json.load(open(map_path, encoding="utf-8"))
errors = []

for key, values in mapping.items():
    if not isinstance(values, list):
        errors.append(f"{key}: value must be a list")
        continue
    for value in values:
        path = os.path.abspath(os.path.join(poc_dir, value))
        if os.path.commonpath([poc_dir, path]) != poc_dir:
            errors.append(f"{key}: out of poc_dir: {value}")
        elif not os.path.exists(path):
            errors.append(f"{key}: missing: {value}")

if errors:
    print("\n".join(errors))
    sys.exit(1)

print("poc-map ok")
PY
```

模板选择规则：

1. 未配置、读取失败或解析失败 `poc_map` 时，加载整个 `poc_dir`。
2. 配置了 `poc_map` 且命中指纹时，加载命中路径和 `_baseline` / `baseline`。
3. 配置了 `poc_map` 但未命中时，只加载 `_fallback` / `fallback` / `_baseline` / `baseline`。
4. 上一步也没有可用路径时，跳过 nuclei。
5. 映射路径必须位于 `poc_dir` 内，越界路径会被忽略。

仓库内的 `poc-map-budget.example.json` 按 `/opt/nuclei_poc/poc_high_quality` 结构整理。换模板库时，先检查路径，再看日志里的 `poc_map_hit_rate` 和 `templates_selected`。

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

产物选择：

| `uname -m` | 产物 |
| --- | --- |
| `x86_64` | `vulnscan-wrapper-linux-amd64` |
| `aarch64` / `arm64` | `vulnscan-wrapper-linux-arm64` |
| `armv7l` | `vulnscan-wrapper-linux-armv7` |

SQLite 使用纯 Go 驱动 `modernc.org/sqlite`，不需要 CGO 或系统 sqlite 开发库。

## 开发检查

```bash
go mod download
go test ./...
go test -cover ./...
go run . --help
go run . scan -h
```

常用定向测试：

```bash
go test -run TestScanAPI ./...
go test -run TestSelectNucleiTemplates ./...
go test -run TestRunScanCLIHelp ./...
go test -run TestScanCLIHosts ./...
```

## 扫描流程

1. API 校验、去重、落库并同步 host 列表。
2. 调度协程每秒查询 `pending` host。
3. worker 标记 host 为 `running` 并绑定 timeout。
4. 有 namespace 时通过 `ip netns exec` 进入子进程；无 namespace 时当前进程直接扫描。
5. 调用 fscan SDK `ScanEach`，映射为资产结果。
6. 对 Web 资产追加轻量 HTTP 指纹。
7. 根据资产 URL、Web 服务和端口生成 nuclei target。
8. 根据资产指纹选择 nuclei templates。
9. nuclei 命中模板时记录 `template-id`。
10. 扫描完成后写入资产、漏洞 ID、漏洞数量和错误信息。

## 日志和排查

systemd 配置中的日志路径：

```text
/var/log/vulnscan/vulnscan-wrapper.log
```

实时查看：

```bash
sudo tail -f /var/log/vulnscan/vulnscan-wrapper.log
```

关键日志示例：

```text
nuclei templates_total=34840 templates_selected=111 template_reduction_ratio=99.7% poc_map_hit_rate=100.0% poc_map_assets_matched=4/4 fallback_full_scan=false skip_nuclei=false fingerprint_hits=http,port:80
```

字段含义：

| 字段 | 说明 |
| --- | --- |
| `templates_selected` | 实际加载的 nuclei 模板数量 |
| `poc_map_hit_rate` | 资产命中 POC map 的比例 |
| `fallback_full_scan=true` | 进入全量模板扫描，优先检查 `VST_POC_MAP` |
| `skip_nuclei=true` | 未命中且没有 fallback/baseline，跳过 nuclei |

30 分钟预算内的起始参数：

```bash
VST_WORKERS=6
VST_NUCLEI_CONCURRENCY=50
VST_NUCLEI_HOST_CONCURRENCY=10
VST_NUCLEI_TIMEOUT=2
VST_HTTP_FINGERPRINT_TIMEOUT=2
```

在 23 个目标 IP、34840 个模板库、预算版 POC map 的环境下，这组参数约 10-12 分钟完成。目标环境、模板质量和网络质量会影响结果。

node_exporter `:9100` 排查不要用宿主机 `127.0.0.1:9100` 代替目标 IP。验证口径：

```bash
ip netns exec <namespace> curl http://<目标IP>:9100/metrics
```

资源抖动时先降 `VST_WORKERS`，再降 `VST_NUCLEI_CONCURRENCY`。生产批量扫描不要使用无 `poc_map` 的全量模板 fallback，除非已经留足总超时和资源预算。

## 安全与限制

- 仅允许个人、内部、研究、测试等非商业用途；未经书面许可禁止商业使用，完整条款见 `LICENSE`。
- HTTP 服务默认监听 `127.0.0.1`；远程访问使用 SSH tunnel。
- nuclei 模板会发起网络请求并执行模板逻辑，`VST_POC_DIR` 必须可信。
- fscan 在本项目中只做资产识别，brute 和 POC 扫描已关闭。
- `namespace` 不能为空，不能是 `.` 或 `..`，不能包含 `/` 或空字节。
- 非 Linux 环境提交非空 namespace 会失败，错误写入对应 host 结果。
