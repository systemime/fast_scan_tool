# Vuln Scan Tool

本项目是一个本地资产与漏洞扫描工具。服务模式下接收 Linux network namespace 下的 host 列表，写入 SQLite，由 worker 池按 host 调度 fscan SDK 做资产识别，再把资产目标交给 nuclei SDK 做漏洞验证。CLI 模式可一次性扫描指定 namespace 下的多个 IP，并输出 JSON 文件。

## 使用发布产物

优先使用 GitHub Releases 中的静态二进制，不需要在目标服务器安装 Go。

下载对应架构产物：

```bash
VERSION=v0.1.0
BASE_URL=https://github.com/systemime/fast_scan_tool/releases/download/${VERSION}

# x86_64
curl -L -o /tmp/vulnscan-wrapper "${BASE_URL}/vulnscan-wrapper-linux-amd64"

# ARM64
curl -L -o /tmp/vulnscan-wrapper "${BASE_URL}/vulnscan-wrapper-linux-arm64"

# ARMv7
curl -L -o /tmp/vulnscan-wrapper "${BASE_URL}/vulnscan-wrapper-linux-armv7"

chmod +x /tmp/vulnscan-wrapper
/tmp/vulnscan-wrapper --help
```

安装到目标服务器：

```bash
sudo install -d -m 0755 /opt/vulnscan /etc/vulnscan /var/lib/vulnscan /var/log/vulnscan
sudo install -m 0755 /tmp/vulnscan-wrapper /opt/vulnscan/vulnscan-wrapper
sudo curl -L -o /etc/vulnscan/poc-map.json "${BASE_URL}/poc-map-budget.example.json"
```

准备 nuclei POC 目录后即可运行：

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_POC_MAP=/etc/vulnscan/poc-map.json \
/opt/vulnscan/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -timeout 600 \
  -workers 6 \
  -total-timeout 1800 \
  -out scan-result.json
```

## 功能概览

- `POST /scan` 提交单个或多个 namespace 扫描任务，仅允许本机请求。
- `GET /scan/{namespace}` 或 `GET /scan?namespace=...` 查询任务状态、资产和漏洞结果。
- SQLite 持久化 namespace、host 状态、资产信息和 nuclei 模板命中结果。
- fscan 以 Go SDK 方式集成，不需要部署外部 `fscan` 二进制。
- fscan 只启用默认安全的 detect 插件，并排除 auth-check、brute、POC、local-effect 能力；nuclei 负责漏洞验证。
- 通过资产指纹和 `poc_map` 缩小 nuclei POC 范围；配置了 `poc_map` 后，未命中只走 fallback/baseline 或跳过 nuclei，避免全量模板拖垮总预算。
- Linux 下通过 `ip netns exec <namespace>` 进入网络命名空间扫描。
- 支持 `amd64`、`arm64`、`armv7` 静态交叉编译。

## 目录关系

当前 `go.mod` 使用本地 replace：

```text
replace github.com/shadow1ng/fscan => ../fscan
```

开发和构建时需要保持目录为：

```text
/opt/project/
  fast_scan_tool/
  fscan/
```

如果项目放在其他目录，也要保证 `fast_scan_tool` 的上一级目录存在同级 `fscan` 源码目录，或者按实际路径修改 `go.mod` 的 replace。

## 开发环境从 0 准备

以下以 Debian/Ubuntu 为例；其他发行版安装同名依赖即可。

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git iproute2
```

安装 Go，版本以 `go.mod` 为准：

```bash
go version
```

准备源码：

```bash
sudo mkdir -p /opt/project
sudo chown "$USER":"$USER" /opt/project
cd /opt/project

git clone <fast_scan_tool_repo_url> fast_scan_tool
git clone <fscan_repo_url> fscan
cd fast_scan_tool
```

拉取 Go 依赖并确认模块关系：

```bash
go mod download
go list -m github.com/shadow1ng/fscan modernc.org/sqlite
```

SQLite 使用纯 Go 驱动 `modernc.org/sqlite`，不需要 CGO 或系统 sqlite 开发库。

## 本地测试

完整测试：

```bash
go test ./...
```

带覆盖率：

```bash
go test -cover ./...
```

常用定向测试：

```bash
go test -run TestScanAPI ./...
go test -run TestSelectNucleiTemplates ./...
go test -run TestRunScanCLIHelp ./...
go test -run TestScanCLIHosts ./...
```

当前测试覆盖：

- namespace 任务重复提交时 host 增删同步。
- API 本地访问限制。
- `POST /scan` 单组和多组请求。
- 空 `ip_hosts` 和未知字段拒绝。
- fscan SDK result 到资产映射。
- nuclei target 聚合。
- POC map allowlist、未命中预算 fallback、越界路径拒绝。
- CLI `--help` / `scan -h`。
- CLI 并发扫描保持输出顺序。
- CLI 总超时取消后不继续提交未开始的 host。

## 本地运行

查看帮助：

```bash
go run . --help
go run . scan -h
```

本地编译并启动 HTTP 服务：

```bash
go build -trimpath -o vulnscan-wrapper .

VST_ADDR=127.0.0.1:8080 \
VST_DB=tasks.db \
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_POC_MAP=./poc-map-budget.example.json \
./vulnscan-wrapper
```

CLI 单次扫描：

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
VST_POC_MAP=./poc-map-budget.example.json \
VST_NUCLEI_CONCURRENCY=50 \
VST_NUCLEI_HOST_CONCURRENCY=10 \
VST_NUCLEI_TIMEOUT=2 \
./vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -timeout 600 \
  -workers 6 \
  -total-timeout 1800 \
  -out scan-result.json
```

CLI 模式不启动 HTTP 服务，不写 SQLite。单个 IP 扫描失败或超过总超时时仍会写出 JSON，并在对应 host 的 `error` 字段记录错误。

## 交叉编译

建议发布静态二进制：

```bash
mkdir -p dist

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-amd64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-arm64 .

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-armv7 .
```

生成校验值：

```bash
sha256sum dist/vulnscan-wrapper-linux-* poc-map-budget.example.json
```

目标平台选择：

| 目标机器 `uname -m` | 使用产物 |
| --- | --- |
| `x86_64` | `vulnscan-wrapper-linux-amd64` |
| `aarch64` / `arm64` | `vulnscan-wrapper-linux-arm64` |
| `armv7l` | `vulnscan-wrapper-linux-armv7` |

交叉编译只证明目标架构可构建；运行测试需要在本机架构、目标机器或带 QEMU 的环境中执行。

从构建机分发到目标服务器：

```bash
scp dist/vulnscan-wrapper-linux-amd64 poc-map-budget.example.json root@x86-target:/tmp/
scp dist/vulnscan-wrapper-linux-arm64 poc-map-budget.example.json root@arm64-target:/tmp/
scp dist/vulnscan-wrapper-linux-armv7 poc-map-budget.example.json root@armv7-target:/tmp/
```

## 发布前检查

发布前至少执行：

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-arm64 .
./dist/vulnscan-wrapper-linux-amd64 --help
./dist/vulnscan-wrapper-linux-amd64 scan -h
```

如果要发 32 位 ARM，再加：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags='-s -w' -o dist/vulnscan-wrapper-linux-armv7 .
```

## 目标服务器从 0 部署

以下命令在目标服务器执行。服务需要进入 network namespace，通常以 `root` 运行最简单。

安装系统依赖：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git iproute2
```

创建目录：

```bash
sudo install -d -m 0755 /opt/vulnscan
sudo install -d -m 0755 /etc/vulnscan
sudo install -d -m 0755 /var/lib/vulnscan
sudo install -d -m 0755 /var/log/vulnscan
sudo install -d -m 0755 /opt/nuclei_poc
```

安装二进制。按目标架构选择一个对应产物：

```bash
sudo install -m 0755 /tmp/vulnscan-wrapper-linux-amd64 /opt/vulnscan/vulnscan-wrapper
# 或：
sudo install -m 0755 /tmp/vulnscan-wrapper-linux-arm64 /opt/vulnscan/vulnscan-wrapper
# 或：
sudo install -m 0755 /tmp/vulnscan-wrapper-linux-armv7 /opt/vulnscan/vulnscan-wrapper
```

安装 POC map：

```bash
sudo install -m 0644 /tmp/poc-map-budget.example.json /etc/vulnscan/poc-map.json
```

准备 nuclei POC 目录。示例使用已经整理好的模板目录：

```bash
sudo git clone <poc_repo_url> /opt/nuclei_poc/poc_high_quality
sudo test -d /opt/nuclei_poc/poc_high_quality
```

如果模板目录不同，后续 `VST_POC_DIR` 和 `poc_map` 中的相对路径要同步调整。

创建环境文件：

```bash
sudo tee /etc/vulnscan/vulnscan.env >/dev/null <<'EOF'
VST_ADDR=127.0.0.1:8080
VST_DB=/var/lib/vulnscan/tasks.db
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality
VST_POC_MAP=/etc/vulnscan/poc-map.json
VST_WORKERS=6
VST_FSCAN_THREADS=256
VST_FSCAN_TIMEOUT=3
VST_NUCLEI_CONCURRENCY=50
VST_NUCLEI_HOST_CONCURRENCY=10
VST_NUCLEI_TIMEOUT=2
VST_HTTP_FINGERPRINT_TIMEOUT=2
EOF
```

说明：

- `VST_ADDR=127.0.0.1:8080` 只允许本机访问 API。远程调用建议走 SSH tunnel。
- `VST_WORKERS * VST_NUCLEI_CONCURRENCY` 是主要并发压力来源。模板库较大时不要同时把两个值拉满。
- 不配置 `VST_POC_MAP` 或 map 读取失败时，会回退全量 `VST_POC_DIR`，耗时和资源占用会明显上升。

## systemd 服务

创建服务文件：

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
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-wrapper
sudo systemctl status vulnscan-wrapper --no-pager
```

如果目标系统的 systemd 不支持 `StandardOutput=append:`，删除 `StandardOutput` / `StandardError` 两行，改用 journald 查看日志：

```bash
journalctl -u vulnscan-wrapper -f
```

## 日志

使用上面的 systemd 配置时，日志写入：

```text
/var/log/vulnscan/vulnscan-wrapper.log
```

实时查看：

```bash
sudo tail -f /var/log/vulnscan/vulnscan-wrapper.log
```

配置 logrotate：

```bash
sudo tee /etc/logrotate.d/vulnscan-wrapper >/dev/null <<'EOF'
/var/log/vulnscan/*.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  copytruncate
}
EOF
```

日志中重点关注：

```text
nuclei templates_total=34840 templates_selected=111 template_reduction_ratio=99.7% poc_map_hit_rate=100.0% poc_map_assets_matched=4/4 fallback_full_scan=false skip_nuclei=false fingerprint_hits=http,port:80
```

- `templates_selected`：实际加载的 nuclei 模板数量。
- `poc_map_hit_rate`：资产命中 POC map 的比例。
- `fallback_full_scan=true`：进入全量模板扫描，通常需要检查 `VST_POC_MAP`。
- `skip_nuclei=true`：未命中且无 fallback/baseline，跳过 nuclei。

## 部署验证

确认二进制可运行：

```bash
/opt/vulnscan/vulnscan-wrapper --help
/opt/vulnscan/vulnscan-wrapper scan -h
```

确认服务监听：

```bash
curl -sS http://127.0.0.1:8080/scan?namespace=not-exists
```

预期返回 `404` 或 namespace 不存在的 JSON 错误，说明 HTTP 服务已响应。

确认 namespace 存在：

```bash
ip netns list
ip netns exec <namespace> ip -br addr
ip netns exec <namespace> ip route
```

提交扫描任务：

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

远程访问本地 API：

```bash
ssh -L 8080:127.0.0.1:8080 root@target-server
curl -sS http://127.0.0.1:8080/scan/ns1
```

## API

所有 API 都只允许 loopback 地址访问；非本机请求返回 `403`。

### 提交单组任务

```http
POST /scan
Content-Type: application/json
```

```json
{
  "namespace": "ns1",
  "ip_hosts": ["10.0.0.1", "10.0.0.2"],
  "timeout": 600
}
```

响应：

```json
{
  "namespace": "ns1",
  "host_count": 2,
  "timeout": 600,
  "added": ["10.0.0.1", "10.0.0.2"],
  "removed": null
}
```

### 提交多组任务

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '[{"namespace":"ns1","ip_hosts":["10.0.0.1","10.0.0.2"],"timeout":600},{"namespace":"ns2","ip_hosts":["10.0.1.1"],"timeout":600}]'
```

批量提交时响应为同顺序的结果数组。

字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `namespace` | string | Linux 网络命名空间名称 |
| `ip_hosts` | string array | 要扫描的 IP/host，会去重并排序；不能为空 |
| `timeout` | int | 单 host 超时时间，单位秒；小于等于 0 时使用 `600` |

## 配置

配置可来自 JSON 文件，也可来自环境变量；环境变量优先。通过 `VST_CONFIG` 或 `CONFIG` 指定 JSON 文件：

```json
{
  "addr": "127.0.0.1:8080",
  "db_path": "/var/lib/vulnscan/tasks.db",
  "poc_dir": "/opt/nuclei_poc/poc_high_quality",
  "poc_map": "/etc/vulnscan/poc-map.json",
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
| `VST_CONFIG` / `CONFIG` | - | 空 | JSON 配置文件路径；环境变量会覆盖配置文件 |
| `VST_ADDR` / `ADDR` | `addr` | `127.0.0.1:8080` | HTTP 监听地址 |
| `VST_DB` / `DB_PATH` | `db_path` | `tasks.db` | SQLite 数据库路径 |
| `VST_POC_DIR` / `POC_DIR` | `poc_dir` | 程序同级 `poc` | nuclei template/POC 目录 |
| `VST_POC_MAP` / `POC_MAP` | `poc_map` | 空 | 资产指纹到 POC 路径映射 |
| `VST_FSCAN_PATH` / `FSCAN_PATH` | `fscan_path` | `fscan` | 兼容旧配置；SDK 主路径不调用外部二进制 |
| `VST_FSCAN_THREADS` / `FSCAN_THREADS` | `fscan_threads` | `256` | fscan SDK 并发线程 |
| `VST_FSCAN_TIMEOUT` / `FSCAN_TIMEOUT` | `fscan_timeout` | `3` | fscan 单探测超时，秒 |
| `VST_FSCAN_PORTS` / `FSCAN_PORTS` | `fscan_ports` | fscan 默认端口 | 逗号分隔端口列表 |
| `VST_WORKERS` / `WORKERS` | `workers` | `CPU * 1.5` 向上取整 | HTTP 服务模式下 host 扫描并发 |
| `VST_NUCLEI_CONCURRENCY` / `NUCLEI_CONCURRENCY` | `nuclei_concurrency` | `25` | 单 host 内 nuclei template 并发 |
| `VST_NUCLEI_HOST_CONCURRENCY` / `NUCLEI_HOST_CONCURRENCY` | `nuclei_host_concurrency` | `1` | 单 host 内 nuclei target 并发 |
| `VST_NUCLEI_TIMEOUT` / `NUCLEI_TIMEOUT` | `nuclei_timeout` | `5` | nuclei 单请求/连接超时，秒 |
| `VST_HTTP_FINGERPRINT_TIMEOUT` / `HTTP_FINGERPRINT_TIMEOUT` | `http_fingerprint_timeout` | `2` | fscan 后追加一次轻量 HTTP 指纹超时，秒；设为 `0` 关闭 |

`fscan_path` 字段保留用于兼容旧配置，但 SDK 主路径不再使用外部二进制。

## POC Map

`poc_map` 是 JSON 文件，key 为资产指纹关键词，value 为 `poc_dir` 下的目录或模板文件：

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

命中指纹时只加载命中的路径和 `_baseline` / `baseline`；配置了 `poc_map` 但未命中指纹时，只加载 `_fallback` / `fallback` / `_baseline` / `baseline`，如果这些都没有配置则跳过 nuclei。只有未配置、读取失败或解析失败 `poc_map` 时，才回退加载整个 `poc_dir`。映射路径必须位于 `poc_dir` 内，越界路径会被忽略。

仓库内的 `poc-map-budget.example.json` 是按 `/opt/nuclei_poc/poc_high_quality` 结构整理的实测起点。换模板库时先确认路径存在，再按日志里的 `poc_map_hit_rate` 和 `templates_selected` 调整。

## 网络命名空间

Linux 下扫描等价于：

```bash
ip netns exec <namespace> /opt/vulnscan/vulnscan-wrapper __scan_host ...
```

要求：

- 运行环境必须是 Linux。
- 系统需要 `ip` 命令。
- 进程需要具备进入目标 netns 的权限。
- `namespace` 不能为空，不能是 `.` 或 `..`，不能包含 `/` 或空字节。

非 Linux 环境提交非空 namespace 时，扫描会失败并在 host 的错误字段中记录原因。

## 扫描流程

1. API 校验、去重、落库并同步 host 列表。
2. 调度协程每秒查询 `pending` host。
3. worker 将 host 标记为 `running` 并绑定 timeout。
4. 有 namespace 时通过 `ip netns exec` 进入子进程；无 namespace 时当前进程直接扫描。
5. 子进程或当前进程调用 fscan SDK `ScanEach`，映射为 `Asset`。
6. 对 Web 资产追加一次轻量 HTTP 指纹。
7. 根据资产 URL、Web 服务和端口生成 nuclei target。
8. 根据资产指纹选择 nuclei templates；配置了 `poc_map` 后，未匹配只走 fallback/baseline 或跳过 nuclei。
9. nuclei callback 命中模板时记录 `template-id`。
10. 扫描完成后写入 `assets`、`vulnerability_ids`、漏洞数量和错误信息。

## 资源参数建议

30 分钟预算内的实测平衡参数：

```bash
VST_WORKERS=6
VST_NUCLEI_CONCURRENCY=50
VST_NUCLEI_HOST_CONCURRENCY=10
VST_NUCLEI_TIMEOUT=2
VST_HTTP_FINGERPRINT_TIMEOUT=2
```

这组参数在 23 个目标 IP、34840 个模板库、预算版 POC map 下，完成时间约 10-12 分钟。目标环境、模板质量、网络质量不同，结果会变化。

资源排查建议：

- 如果目标机器的 node_exporter `:9100` 报错，验证口径应是 `ip netns exec <namespace> curl http://<目标IP>:9100/metrics`，不要用宿主机 `127.0.0.1:9100` 代替。
- 如出现监控抖动，先降低 `VST_WORKERS`，再降低 `VST_NUCLEI_CONCURRENCY`。
- 不要在生产批量扫描中使用无 `poc_map` 的全量模板 fallback，除非总超时和资源预算足够。

## 安全注意事项

- 本项目仅允许个人、内部、研究、测试等非商业用途；未经书面许可禁止商业使用，完整条款见 `LICENSE`。
- HTTP 服务默认只监听 `127.0.0.1`；如需远程访问，建议使用 SSH tunnel。
- nuclei template 可执行网络请求和模板逻辑，`VST_POC_DIR` 必须可信。
- fscan 当前关闭 brute 和 POC 扫描，本项目只把 fscan 用作资产识别。
- 生产环境建议保留 `VST_POC_MAP`，并定期根据 `poc_map_hit_rate` 调整映射。
