# Fast Scan Tool

纯 Python 版 Linux network namespace 资产扫描和漏洞验证工具。代码只依赖 Python 标准库；运行扫描时调用系统里的 `fscan` 和 `nuclei` 命令行程序，HTTP 服务用 SQLite 保存任务。

## 功能

- CLI：一次性扫描 namespace 内的一组 IP，输出 JSON。
- HTTP：本机 API 提交/查询任务，后台 worker 自动扫描。
- 扫描链路：`ip netns exec` → `fscan` 资产识别 → HTTP 指纹补充 → `nuclei` 验证。
- 并发：默认本进程线程 worker；需要分布式/动态 worker 数时可切到 Celery。
- 发布：可直接部署源码，也可用 Nuitka 编译为 standalone/onefile 二进制。

## 安装

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv iproute2

# fscan 与 nuclei 请按各自项目安装，并放到 PATH，或用 VST_FSCAN_PATH/VST_NUCLEI_PATH 指定。
python3 -m venv /opt/vulnscan/venv
/opt/vulnscan/venv/bin/pip install -U pip
/opt/vulnscan/venv/bin/pip install .
```

准备 nuclei 模板：

```bash
sudo git clone https://github.com/adysec/nuclei_poc.git /opt/nuclei_poc
```

打包后的 Python 二进制不内嵌 `fscan`、`nuclei` 或 POC 仓库；测试机/生产机必须提前提供这两个可执行文件，并用 `VST_FSCAN_PATH`、`VST_NUCLEI_PATH`、`VST_POC_DIR` 指定位置。`VST_POC_DIR` 指到哪个 POC 仓库或目录，程序就直接使用哪个目录。

## CLI 最小使用

```bash
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality \
/opt/vulnscan/venv/bin/vulnscan-wrapper scan \
  -namespace ns1 \
  -ips 10.0.0.1,10.0.0.2 \
  -out scan-result.json
```

输出：

```json
{
  "namespace": "ns1",
  "hosts": [
    {
      "ip": "10.0.0.1",
      "assets": [
        {"type":"SERVICE","target":"10.0.0.1","port":80,"service":"http","url":"http://10.0.0.1:80","is_web":true}
      ],
      "vulnerabilities": 1,
      "vulnerability_ids": ["CVE-2024-0001"]
    }
  ]
}
```

## HTTP 服务部署

```bash
sudo install -d -m 0755 /opt/vulnscan /etc/vulnscan /var/lib/vulnscan /var/log/vulnscan
sudo cp -r . /opt/vulnscan/src
python3 -m venv /opt/vulnscan/venv
/opt/vulnscan/venv/bin/pip install /opt/vulnscan/src

sudo tee /etc/vulnscan/vulnscan.env >/dev/null <<'EOF'
VST_ADDR=127.0.0.1:8080
VST_DB=/var/lib/vulnscan/tasks.db
VST_POC_DIR=/opt/nuclei_poc/poc_high_quality
VST_FSCAN_PATH=/usr/local/bin/fscan
VST_NUCLEI_PATH=/usr/local/bin/nuclei
VST_WORKERS=6
EOF

sudo tee /etc/systemd/system/vulnscan-wrapper.service >/dev/null <<'EOF'
[Unit]
Description=Fast Scan Tool
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/vulnscan/vulnscan.env
WorkingDirectory=/opt/vulnscan
ExecStart=/opt/vulnscan/venv/bin/vulnscan-wrapper
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan-wrapper
```

提交和查询：

```bash
curl -sS http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"ns1","ip_hosts":["10.0.0.1","10.0.0.2"],"timeout":600}'

curl -sS http://127.0.0.1:8080/scan/ns1
curl -sS 'http://127.0.0.1:8080/scan?namespace=ns1'
```

API 只接受本机请求；远程访问用 SSH tunnel：

```bash
ssh -L 8080:127.0.0.1:8080 root@target-server
```

## Celery 分布式 / 动态 worker 数

默认 `VST_QUEUE=local`，由服务进程内线程扫描。需要多进程或分布式时启用 Celery：

```bash
/opt/vulnscan/venv/bin/pip install '/opt/vulnscan/src[celery]'

sudo tee -a /etc/vulnscan/vulnscan.env >/dev/null <<'EOF'
VST_QUEUE=celery
VST_CELERY_BROKER=redis://127.0.0.1:6379/0
VST_CELERY_BACKEND=redis://127.0.0.1:6379/1
EOF
```

启动 worker，`--autoscale=max,min` 会按队列压力动态伸缩进程数：

```bash
cd /opt/vulnscan
. /opt/vulnscan/venv/bin/activate
celery -A fast_scan_tool.celery_app worker --loglevel=INFO --concurrency=4 --autoscale=16,2 -n vulnscan@%h
```

如果没有启用 `--autoscale`，也可以运行中临时调节固定 worker 池：

```bash
celery -A fast_scan_tool.celery_app worker --loglevel=INFO --concurrency=4 -n vulnscan@%h
celery -A fast_scan_tool.celery_app control pool_grow 4
celery -A fast_scan_tool.celery_app control pool_shrink 2
```

启用 `--autoscale` 时让 autoscaler 控制池大小，不要混用 `pool_grow/pool_shrink`。多机部署时让 HTTP 服务和 Celery worker 使用同一个 broker，并确保 worker 能访问同一个 `VST_DB` 路径或改成共享数据库实现；SQLite 更适合同机多进程。

## Nuitka 源码保护 / 二进制发布

Nuitka 官方文档说明，`--mode=standalone`、`--mode=onefile`、`--mode=app` 生成的程序可以脱离目标机 Python 安装运行；默认 accelerated mode 不适合当可搬运二进制发布。参考：[Nuitka User Manual](https://nuitka.net/user-documentation/user-manual.html)。

安装构建依赖：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install '.[build]'
```

Standalone 目录发布：

```bash
python -m nuitka --mode=standalone --assume-yes-for-downloads \
  --python-flag=-m \
  --output-dir=dist \
  --output-filename=vulnscan-wrapper \
  fast_scan_tool
```

Onefile 单文件发布：

```bash
python -m nuitka --mode=onefile --assume-yes-for-downloads \
  --python-flag=-m \
  --output-dir=dist \
  --output-filename=vulnscan-wrapper-linux-amd64 \
  fast_scan_tool
```

部署 onefile：

```bash
sudo install -m 0755 dist/vulnscan-wrapper-linux-amd64 /opt/vulnscan/vulnscan-wrapper
sudo sed -i 's#ExecStart=.*#ExecStart=/opt/vulnscan/vulnscan-wrapper#' /etc/systemd/system/vulnscan-wrapper.service
sudo systemctl daemon-reload
sudo systemctl restart vulnscan-wrapper
```

这类编译发布不会发布 `.py` 源码；需要更强的数据文件隐藏/商业保护能力时，再评估 Nuitka Commercial。

## 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VST_ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `VST_DB` | `tasks.db` | SQLite 文件 |
| `VST_POC_DIR` | 程序目录下 `poc` | nuclei 模板目录 |
| `VST_FSCAN_PATH` | `fscan` | fscan 命令路径 |
| `VST_NUCLEI_PATH` | `nuclei` | nuclei 命令路径 |
| `VST_FSCAN_PORTS` | 空 | 逗号分隔端口，如 `22,80,443` |
| `VST_FSCAN_ARGS` | 空 | 追加给 fscan 的参数 |
| `VST_NUCLEI_ARGS` | 空 | 追加给 nuclei 的参数 |
| `VST_WORKERS` | `ceil(cpu*1.5)` | local 模式 worker 数 |
| `VST_QUEUE` | `local` | `local` 或 `celery` |
| `VST_CELERY_BROKER` | `redis://127.0.0.1:6379/0` | Celery broker |
| `VST_CELERY_BACKEND` | `redis://127.0.0.1:6379/1` | Celery result backend |

## 开发验证

```bash
python -m unittest -v
python -m fast_scan_tool --help
```

## 参考

- Nuitka User Manual: <https://nuitka.net/user-documentation/user-manual.html>
- Celery Workers Guide: <https://docs.celeryq.dev/en/stable/userguide/workers.html>
- Celery app control reference: <https://docs.celeryq.dev/en/main/reference/celery.app.control.html>
