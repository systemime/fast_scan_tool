#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import html
import ipaddress
import json
import logging
from contextlib import suppress
import math
import os
import queue
import re
import shlex
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "completed"
STATUS_TIMEOUT = "timeout"
DEFAULT_TIMEOUT_SECONDS = 600


@dataclass
class Asset:
    type: str = ""
    target: str = ""
    port: int = 0
    service: str = ""
    protocol: str = ""
    url: str = ""
    title: str = ""
    server: str = ""
    banner: str = ""
    status: str = ""
    status_code: int = 0
    fingerprints: list[str] = field(default_factory=list)
    vulnerability: str = ""
    is_web: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        return {k: v for k, v in data.items() if v not in ("", 0, False, [], None)}


@dataclass
class Config:
    addr: str = "127.0.0.1:8080"
    db_path: str = "tasks.db"
    poc_dir: str = "poc"
    fscan_path: str = "fscan"
    nuclei_path: str = "nuclei"
    fscan_threads: int = 256
    fscan_timeout: int = 3
    fscan_ports: list[int] = field(default_factory=list)
    workers: int = max(1, math.ceil((os.cpu_count() or 1) * 1.5))
    queue_mode: str = "local"
    celery_broker: str = "redis://127.0.0.1:6379/0"
    celery_backend: str = "redis://127.0.0.1:6379/1"
    nuclei_concurrency: int = 25
    nuclei_host_concurrency: int = 1
    nuclei_timeout: int = 5
    http_fingerprint_timeout: int = 2
    fscan_args: str = ""
    nuclei_args: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        fields = {f.name for f in dataclasses.fields(cls)}
        cfg = cls(**{k: v for k, v in data.items() if k in fields})
        cfg.fscan_ports = parse_port_list(cfg.fscan_ports if isinstance(cfg.fscan_ports, str) else format_port_list(cfg.fscan_ports))
        return cfg.normalized()

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def normalized(self) -> "Config":
        if not self.addr:
            self.addr = "127.0.0.1:8080"
        if not self.db_path:
            self.db_path = "tasks.db"
        if not self.poc_dir:
            self.poc_dir = str(Path(sys.argv[0]).resolve().parent / "poc")
        if not self.fscan_path:
            self.fscan_path = "fscan"
        if not self.nuclei_path:
            self.nuclei_path = "nuclei"
        self.fscan_threads = max(1, int(self.fscan_threads or 256))
        self.fscan_timeout = max(1, int(self.fscan_timeout or 3))
        self.workers = max(1, int(self.workers or 1))
        self.nuclei_concurrency = max(1, int(self.nuclei_concurrency or 25))
        self.nuclei_host_concurrency = max(1, int(self.nuclei_host_concurrency or 1))
        self.nuclei_timeout = max(1, int(self.nuclei_timeout or 5))
        self.http_fingerprint_timeout = max(0, int(self.http_fingerprint_timeout or 0))
        self.queue_mode = (self.queue_mode or "local").strip().lower()
        if self.queue_mode not in {"local", "celery"}:
            self.queue_mode = "local"
        return self


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str | None) -> str | None:
    return value or None


def unique_sorted(values: list[str]) -> list[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})


def normalize_hosts(hosts: list[str]) -> list[str]:
    return unique_sorted(hosts)


def valid_namespace(namespace: str) -> bool:
    return bool(namespace and namespace not in {".", ".."} and "/" not in namespace and "\x00" not in namespace)


def parse_port_list(value: str) -> list[int]:
    ports: set[int] = set()
    for part in str(value or "").split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError("invalid port list")
        ports.add(port)
    return sorted(ports)


def format_port_list(ports: list[int]) -> str:
    return ",".join(str(p) for p in sorted({int(p) for p in ports if int(p) > 0}))


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True) if Path(path).parent != Path(".") else None
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA busy_timeout=30000")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.init()

    def close(self) -> None:
        self.db.close()

    def init(self) -> None:
        self.db.executescript(
            """
CREATE TABLE IF NOT EXISTS namespaces (
  namespace TEXT PRIMARY KEY,
  timeout_seconds INTEGER NOT NULL,
  host_count INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  namespace TEXT NOT NULL,
  ip TEXT NOT NULL,
  status TEXT NOT NULL,
  timeout_seconds INTEGER NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  vulnerabilities INTEGER NOT NULL DEFAULT 0,
  vulnerability_ids TEXT NOT NULL DEFAULT '[]',
  assets TEXT NOT NULL DEFAULT '[]',
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (namespace, ip),
  FOREIGN KEY (namespace) REFERENCES namespaces(namespace) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
"""
        )
        self.db.execute(
            """UPDATE hosts SET status = CASE status
WHEN '未开始' THEN ? WHEN '进行中' THEN ? WHEN '已完成' THEN ? WHEN '超时' THEN ? ELSE status END""",
            (STATUS_PENDING, STATUS_RUNNING, STATUS_DONE, STATUS_TIMEOUT),
        )
        self.db.commit()

    def reset_running(self) -> None:
        with self.lock:
            self.db.execute("UPDATE hosts SET status=?, started_at=NULL, updated_at=? WHERE status=?", (STATUS_PENDING, now_text(), STATUS_RUNNING))
            self.db.commit()

    def upsert_task(self, namespace: str, hosts: list[str], timeout: int) -> dict[str, Any]:
        hosts = normalize_hosts(hosts)
        result = {"namespace": namespace, "host_count": len(hosts), "timeout": timeout, "added": [], "removed": []}
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                now = now_text()
                self.db.execute(
                    """INSERT INTO namespaces(namespace, timeout_seconds, host_count, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(namespace) DO UPDATE SET timeout_seconds=excluded.timeout_seconds, host_count=excluded.host_count, updated_at=excluded.updated_at""",
                    (namespace, timeout, len(hosts), now),
                )
                existing = {r["ip"]: r["status"] for r in self.db.execute("SELECT ip, status FROM hosts WHERE namespace=?", (namespace,))}
                wanted = set(hosts)
                for ip, status in existing.items():
                    if ip not in wanted:
                        self.db.execute("DELETE FROM hosts WHERE namespace=? AND ip=?", (namespace, ip))
                        result["removed"].append(ip)
                    elif status == STATUS_PENDING:
                        self.db.execute("UPDATE hosts SET timeout_seconds=?, updated_at=? WHERE namespace=? AND ip=?", (timeout, now, namespace, ip))
                for host in hosts:
                    if host in existing:
                        continue
                    self.db.execute(
                        "INSERT INTO hosts(namespace, ip, status, timeout_seconds, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (namespace, host, STATUS_PENDING, timeout, now),
                    )
                    result["added"].append(host)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        result["added"].sort(); result["removed"].sort()
        return result

    def get_task(self, namespace: str) -> dict[str, Any]:
        with self.lock:
            row = self.db.execute("SELECT namespace, timeout_seconds, host_count FROM namespaces WHERE namespace=?", (namespace,)).fetchone()
            if not row:
                raise KeyError(namespace)
            hosts = []
            for host in self.db.execute(
                """SELECT ip, status, timeout_seconds, vulnerabilities, vulnerability_ids, assets, started_at, finished_at, last_error
FROM hosts WHERE namespace=? ORDER BY ip""",
                (namespace,),
            ):
                hosts.append(
                    {
                        "ip": host["ip"],
                        "status": host["status"],
                        "timeout": host["timeout_seconds"],
                        "assets": [a.to_dict() for a in unique_assets([Asset(**a) for a in json.loads(host["assets"] or "[]")])],
                        "vulnerabilities": host["vulnerabilities"],
                        "vulnerability_ids": unique_sorted(json.loads(host["vulnerability_ids"] or "[]")),
                        "started_at": parse_time(host["started_at"]),
                        "finished_at": parse_time(host["finished_at"]),
                        "last_error": host["last_error"] or None,
                    }
                )
        return {"namespace": row["namespace"], "host_count": row["host_count"], "timeout": row["timeout_seconds"], "hosts": strip_none(hosts)}

    def pending_hosts(self) -> list[tuple[str, str]]:
        with self.lock:
            return [(r["namespace"], r["ip"]) for r in self.db.execute("SELECT namespace, ip FROM hosts WHERE status=? ORDER BY updated_at, namespace, ip", (STATUS_PENDING,))]

    def begin_host(self, namespace: str, ip: str) -> tuple[int, bool]:
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                row = self.db.execute("SELECT status, timeout_seconds FROM hosts WHERE namespace=? AND ip=?", (namespace, ip)).fetchone()
                if not row or row["status"] != STATUS_PENDING:
                    self.db.rollback()
                    return 0, False
                now = now_text()
                self.db.execute(
                    """UPDATE hosts SET status=?, started_at=?, finished_at=NULL, vulnerabilities=0,
 vulnerability_ids='[]', assets='[]', last_error='', updated_at=? WHERE namespace=? AND ip=? AND status=?""",
                    (STATUS_RUNNING, now, now, namespace, ip, STATUS_PENDING),
                )
                self.db.commit()
                return int(row["timeout_seconds"]), True
            except Exception:
                self.db.rollback()
                raise

    def complete_host(self, namespace: str, ip: str, ids: list[str], assets: list[Asset], error: Exception | str | None = None) -> None:
        ids = unique_sorted(ids)
        assets_dicts = [a.to_dict() for a in unique_assets(assets)]
        with self.lock:
            self.db.execute(
                """UPDATE hosts SET status=?, finished_at=?, vulnerabilities=?, vulnerability_ids=?, assets=?, last_error=?, updated_at=?
WHERE namespace=? AND ip=? AND status=?""",
                (STATUS_DONE, now_text(), len(ids), json.dumps(ids), json.dumps(assets_dicts, ensure_ascii=False), str(error or ""), now_text(), namespace, ip, STATUS_RUNNING),
            )
            self.db.commit()

    def timeout_host(self, namespace: str, ip: str) -> None:
        with self.lock:
            self.db.execute(
                "UPDATE hosts SET status=?, finished_at=?, last_error='scan timeout', updated_at=? WHERE namespace=? AND ip=? AND status=?",
                (STATUS_TIMEOUT, now_text(), now_text(), namespace, ip, STATUS_RUNNING),
            )
            self.db.commit()

    def overdue_hosts(self) -> list[tuple[str, str]]:
        now = datetime.now(timezone.utc)
        jobs = []
        with self.lock:
            rows = self.db.execute("SELECT namespace, ip, started_at, timeout_seconds FROM hosts WHERE status=? AND started_at IS NOT NULL", (STATUS_RUNNING,))
            for row in rows:
                try:
                    started = datetime.fromisoformat(row["started_at"])
                except ValueError:
                    jobs.append((row["namespace"], row["ip"])); continue
                if now > started + timedelta(seconds=int(row["timeout_seconds"])):
                    jobs.append((row["namespace"], row["ip"]))
        return jobs


def strip_none(value: Any) -> Any:
    if isinstance(value, list):
        return [strip_none(v) for v in value]
    if isinstance(value, dict):
        return {k: strip_none(v) for k, v in value.items() if v is not None}
    return value


def unique_assets(values: list[Asset]) -> list[Asset]:
    seen: set[tuple[str, str, str, int]] = set()
    out: list[Asset] = []
    for asset in values:
        if not asset.target:
            continue
        asset.fingerprints = unique_sorted(asset.fingerprints)
        key = (asset.type, asset.target, asset.url, int(asset.port or 0))
        if key in seen:
            continue
        seen.add(key)
        out.append(asset)
    return sorted(out, key=lambda a: (a.target, a.port, a.url, a.type))


def load_config() -> Config:
    cfg = Config(poc_dir=str(Path(sys.argv[0]).resolve().parent / "poc"))
    config_path = first_env("VST_CONFIG", "CONFIG")
    if config_path:
        cfg = Config.from_dict(json.loads(Path(config_path).read_text()))
    env_map = {
        "addr": ("VST_ADDR", "ADDR"),
        "db_path": ("VST_DB", "DB_PATH"),
        "poc_dir": ("VST_POC_DIR", "POC_DIR"),
        "fscan_path": ("VST_FSCAN_PATH", "FSCAN_PATH"),
        "nuclei_path": ("VST_NUCLEI_PATH", "NUCLEI_PATH"),
        "queue_mode": ("VST_QUEUE", "QUEUE"),
        "celery_broker": ("VST_CELERY_BROKER", "CELERY_BROKER_URL"),
        "celery_backend": ("VST_CELERY_BACKEND", "CELERY_RESULT_BACKEND"),
        "fscan_args": ("VST_FSCAN_ARGS",),
        "nuclei_args": ("VST_NUCLEI_ARGS",),
    }
    for name, keys in env_map.items():
        if value := first_env(*keys):
            setattr(cfg, name, value)
    int_map = {
        "fscan_threads": ("VST_FSCAN_THREADS", "FSCAN_THREADS"),
        "fscan_timeout": ("VST_FSCAN_TIMEOUT", "FSCAN_TIMEOUT"),
        "workers": ("VST_WORKERS", "WORKERS"),
        "nuclei_concurrency": ("VST_NUCLEI_CONCURRENCY", "NUCLEI_CONCURRENCY"),
        "nuclei_host_concurrency": ("VST_NUCLEI_HOST_CONCURRENCY", "NUCLEI_HOST_CONCURRENCY"),
        "nuclei_timeout": ("VST_NUCLEI_TIMEOUT", "NUCLEI_TIMEOUT"),
        "http_fingerprint_timeout": ("VST_HTTP_FINGERPRINT_TIMEOUT", "HTTP_FINGERPRINT_TIMEOUT"),
    }
    for name, keys in int_map.items():
        if value := first_env(*keys):
            with suppress(ValueError):
                setattr(cfg, name, int(value))
    if value := first_env("VST_FSCAN_PORTS", "FSCAN_PORTS"):
        cfg.fscan_ports = parse_port_list(value)
    return cfg.normalized()


def first_env(*keys: str) -> str:
    for key in keys:
        if value := os.environ.get(key, "").strip():
            return value
    return ""


class App:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self.jobs: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=cfg.workers)
        self.queued: set[tuple[str, str]] = set()
        self.queued_lock = threading.Lock()
        self.stop = threading.Event()

    def start(self) -> None:
        if self.cfg.queue_mode == "local":
            for _ in range(self.cfg.workers):
                threading.Thread(target=self.worker, daemon=True).start()
        threading.Thread(target=self.loop, args=(1, self.dispatch_pending), daemon=True).start()
        threading.Thread(target=self.loop, args=(60, self.enforce_timeouts), daemon=True).start()

    def loop(self, interval: int, fn) -> None:
        while not self.stop.is_set():
            try:
                fn()
            except Exception:
                logging.exception("background loop failed")
            self.stop.wait(interval)

    def worker(self) -> None:
        while not self.stop.is_set():
            try:
                namespace, ip = self.jobs.get(timeout=1)
            except queue.Empty:
                continue
            with self.queued_lock:
                self.queued.discard((namespace, ip))
            try:
                timeout, ok = self.store.begin_host(namespace, ip)
                if not ok:
                    continue
                result, error = scan_host(self.cfg, namespace, ip, timeout)
                if error == "scan timeout":
                    self.store.timeout_host(namespace, ip)
                else:
                    self.store.complete_host(namespace, ip, result.get("vulnerability_ids", []), result.get("assets", []), error)
            except Exception as exc:
                logging.exception("scan %s/%s failed", namespace, ip)
                self.store.complete_host(namespace, ip, [], [], exc)
            finally:
                self.jobs.task_done()

    def dispatch_pending(self) -> None:
        for namespace, ip in self.store.pending_hosts():
            if self.cfg.queue_mode == "celery":
                self.dispatch_celery(namespace, ip)
            elif not self.try_queue(namespace, ip):
                return

    def try_queue(self, namespace: str, ip: str) -> bool:
        with self.queued_lock:
            if (namespace, ip) in self.queued:
                return True
            self.queued.add((namespace, ip))
        try:
            self.jobs.put_nowait((namespace, ip))
            return True
        except queue.Full:
            with self.queued_lock:
                self.queued.discard((namespace, ip))
            return False

    def dispatch_celery(self, namespace: str, ip: str) -> None:
        timeout, ok = self.store.begin_host(namespace, ip)
        if not ok:
            return
        if celery_app is None:
            self.store.complete_host(namespace, ip, [], [], "celery is not installed")
            return
        celery_app.send_task("vulnscan.scan_host", args=[namespace, ip, timeout, self.cfg.to_dict()])

    def enforce_timeouts(self) -> None:
        for namespace, ip in self.store.overdue_hosts():
            self.store.timeout_host(namespace, ip)

    def upsert_scan_request(self, req: dict[str, Any]) -> dict[str, Any]:
        namespace = str(req.get("namespace", "")).strip()
        hosts = normalize_hosts([str(h) for h in req.get("ip_hosts", [])])
        timeout = int(req.get("timeout") or DEFAULT_TIMEOUT_SECONDS)
        if not valid_namespace(namespace):
            raise ValueError("namespace is required")
        if not hosts:
            raise ValueError("ip_hosts is required")
        return self.store.upsert_task(namespace, hosts, timeout)


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            logging.info("%s - " + fmt, self.address_string(), *args)

        def local_only(self) -> bool:
            try:
                return ipaddress.ip_address(self.client_address[0]).is_loopback
            except ValueError:
                return False

        def write_json(self, status: int, value: Any) -> None:
            data = json.dumps(strip_none(value), ensure_ascii=False).encode() + b"\n"
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def write_error(self, status: int, message: str) -> None:
            self.write_json(status, {"error": message})

        def do_POST(self) -> None:
            if not self.local_only():
                self.write_error(403, "local requests only"); return
            if self.path != "/scan":
                self.write_error(404, "not found"); return
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 2 << 20)
                raw = self.rfile.read(length)
                body = json.loads(raw or b"")
                batch = isinstance(body, list)
                requests = body if batch else [body]
                if not requests:
                    raise ValueError("empty scan request list")
                results = [app.upsert_scan_request(req) for req in requests]
                self.write_json(200, results if batch else results[0])
            except Exception as exc:
                self.write_error(400, str(exc))

        def do_GET(self) -> None:
            if not self.local_only():
                self.write_error(403, "local requests only"); return
            parsed = urllib.parse.urlparse(self.path)
            namespace = ""
            if parsed.path == "/scan":
                namespace = urllib.parse.parse_qs(parsed.query).get("namespace", [""])[0].strip()
            elif parsed.path.startswith("/scan/"):
                namespace = parsed.path.removeprefix("/scan/").strip("/")
            if not namespace:
                self.write_error(400, "missing namespace"); return
            try:
                self.write_json(200, app.store.get_task(namespace))
            except KeyError:
                self.write_error(404, "namespace not found")
            except Exception as exc:
                self.write_error(500, str(exc))
    return Handler


def serve(cfg: Config) -> None:
    store = Store(cfg.db_path)
    store.reset_running()
    app = App(cfg, store)
    app.start()
    host, port = cfg.addr.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), make_handler(app))
    logging.info("listening on http://%s poc_dir=%s queue=%s workers=%s", cfg.addr, cfg.poc_dir, cfg.queue_mode, cfg.workers)
    try:
        server.serve_forever()
    finally:
        app.stop.set()
        server.server_close()
        store.close()


def scan_host(cfg: Config, namespace: str, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    if namespace:
        if sys.platform != "linux":
            return {}, f'network namespace {namespace!r} requires linux'
        return scan_host_process(cfg, namespace, ip, timeout)
    return scan_direct(cfg, ip, timeout)


def scan_host_process(cfg: Config, namespace: str, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    cmd = ["ip", "netns", "exec", namespace, *child_command(), "__scan_host",
           "--poc-dir", cfg.poc_dir, "--fscan-path", cfg.fscan_path, "--nuclei-path", cfg.nuclei_path,
           "--fscan-threads", str(cfg.fscan_threads), "--fscan-timeout", str(cfg.fscan_timeout),
           "--fscan-ports", format_port_list(cfg.fscan_ports),
           "--nuclei-concurrency", str(cfg.nuclei_concurrency), "--nuclei-host-concurrency", str(cfg.nuclei_host_concurrency),
           "--nuclei-timeout", str(cfg.nuclei_timeout), "--http-fingerprint-timeout", str(cfg.http_fingerprint_timeout),
           "--fscan-args", cfg.fscan_args, "--nuclei-args", cfg.nuclei_args, "--target", ip]
    rc, out, err, timed_out = run_process(cmd, timeout)
    if err.strip():
        logging.info(err.strip())
    if timed_out:
        return {}, "scan timeout"
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError as exc:
        return {}, f"invalid child json: {exc}"
    assets = [Asset(**a) for a in data.get("assets", [])]
    return {"vulnerability_ids": data.get("vulnerability_ids", []), "assets": assets}, data.get("error") or (err.strip() if rc else "")


def child_command() -> list[str]:
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        return [str(Path(sys.argv[0]).resolve())]
    return [sys.executable, "-m", "vulnscan_tool"]


def scan_direct(cfg: Config, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + max(1, timeout)
    errors: list[str] = []
    assets, err = run_fscan(cfg, ip, remaining(deadline))
    if err:
        errors.append(err)
    assets = enrich_http_fingerprints(cfg, assets, remaining(deadline))
    logging.info("nuclei poc_dir=%s", cfg.poc_dir)
    ids: list[str] = []
    ids, err = scan_nuclei_targets(cfg, nuclei_targets(ip, assets), [], remaining(deadline))
    if err:
        errors.append(err)
    return {"vulnerability_ids": unique_sorted(ids), "assets": assets}, "; ".join(e for e in errors if e)


def remaining(deadline: float) -> int:
    if deadline == float("inf"):
        return 24 * 60 * 60
    return max(1, int(deadline - time.monotonic()))


def run_fscan(cfg: Config, ip: str, timeout: int) -> tuple[list[Asset], str]:
    if not shutil.which(cfg.fscan_path) and not Path(cfg.fscan_path).exists():
        return [], f"fscan not found: {cfg.fscan_path}"
    cmd = [cfg.fscan_path, "-h", ip, "-nobr", "-nopoc", "-np", "-t", str(cfg.fscan_threads)]
    if cfg.fscan_ports:
        cmd += ["-p", format_port_list(cfg.fscan_ports)]
    cmd += shlex.split(cfg.fscan_args)
    rc, out, err, timed_out = run_process(cmd, timeout)
    if timed_out:
        return [], "fscan timeout"
    assets = unique_assets([asset for line in out.splitlines() for asset in parse_fscan_line(line, ip)])
    return assets, "" if rc == 0 else (err.strip() or f"fscan exited {rc}")


def parse_fscan_line(line: str, host: str = "") -> list[Asset]:
    line = line.strip()
    if not line:
        return []
    if line.startswith("{"):
        with suppress(json.JSONDecodeError):
            return [asset_from_mapping(json.loads(line), host)]
    assets: list[Asset] = []
    for url in re.findall(r"https?://[^\s'\"<>]+", line, re.I):
        parsed = urllib.parse.urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        assets.append(Asset(type="SERVICE", target=parsed.hostname or host, port=port, service=parsed.scheme, protocol=parsed.scheme, url=url, is_web=True))
    m = re.search(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9_.:-]+):(?P<port>\d{1,5})\s*(?P<svc>[a-zA-Z0-9_-]+)?", line)
    if m:
        port = int(m.group("port"))
        svc = (m.group("svc") or "").lower()
        assets.append(Asset(type="SERVICE", target=m.group("host"), port=port, service=svc, protocol=svc, is_web=svc in {"http", "https"}))
    return assets


def asset_from_mapping(data: dict[str, Any], host: str = "") -> Asset:
    details = data.get("details") if isinstance(data.get("details"), dict) else data
    asset = Asset(
        type=str(data.get("type") or "SERVICE").upper(),
        target=str(data.get("target") or data.get("host") or data.get("ip") or host).strip(),
        status=str(data.get("status") or "").strip(),
        port=to_int(details.get("port")),
        service=str(details.get("service") or details.get("protocol") or "").lower().strip(),
        protocol=str(details.get("protocol") or "").lower().strip(),
        url=str(details.get("url") or "").strip(),
        title=str(details.get("title") or "").strip(),
        server=str(details.get("server") or "").strip(),
        banner=str(details.get("banner") or "").strip(),
        status_code=to_int(details.get("status_code") or details.get("status")),
        fingerprints=detail_strings(details.get("fingerprints")),
        vulnerability=str(details.get("vulnerability") or "").strip(),
        is_web=bool(details.get("is_web")),
    )
    if asset.url and not asset.target:
        asset.target = urllib.parse.urlparse(asset.url).hostname or ""
    if asset.url or asset.service in {"http", "https"} or asset.protocol in {"http", "https"} or asset.status_code or asset.server or asset.title:
        asset.is_web = True
        asset.url = asset.url or build_url(asset)
    return asset


def to_int(value: Any) -> int:
    with suppress(Exception):
        return int(value)
    return 0


def detail_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return unique_sorted([str(v) for v in value])
    if isinstance(value, str):
        return unique_sorted(re.split(r"[,;]", value))
    return []


def enrich_http_fingerprints(cfg: Config, assets: list[Asset], timeout: int) -> list[Asset]:
    if cfg.http_fingerprint_timeout <= 0:
        return assets
    out = [dataclasses.replace(a) for a in assets]
    ctx = ssl._create_unverified_context()
    for asset in out:
        url = http_fingerprint_url(asset)
        if not url:
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-wrapper"})
            with urllib.request.urlopen(req, timeout=min(cfg.http_fingerprint_timeout, timeout), context=ctx) as resp:
                body = resp.read(65536)
                headers = resp.headers
            asset.server = asset.server or headers.get("Server", "")
            asset.title = asset.title or html_title(body)
            asset.fingerprints = unique_sorted(asset.fingerprints + http_fingerprint_values(headers, body))
            asset.is_web = True
        except Exception:
            continue
    return unique_assets(out)


def http_fingerprint_url(asset: Asset) -> str:
    if "://" in asset.url:
        return asset.url
    if asset.is_web or asset.service in {"http", "https"} or asset.protocol in {"http", "https"}:
        return build_url(asset)
    return ""


def http_fingerprint_values(headers, body: bytes) -> list[str]:
    values = [headers.get("Server", ""), headers.get("X-Powered-By", ""), headers.get("WWW-Authenticate", ""), html_title(body)]
    cookies = headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []
    values += ["cookie:" + c.split("=", 1)[0] for c in cookies if "=" in c]
    lower = body.decode("utf-8", "ignore").lower()
    for keyword in "spring thinkphp wordpress jenkins weblogic nacos elasticsearch elastic kibana wazuh nginx tomcat grafana prometheus gitlab harbor minio".split():
        if keyword in lower:
            values.append(keyword)
    return unique_sorted(values)


def html_title(body: bytes) -> str:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", m.group(1).decode("utf-8", "ignore")).strip()) if m else ""


def scan_nuclei_targets(cfg: Config, targets: list[str], templates: list[str], timeout: int) -> tuple[list[str], str]:
    if not targets:
        return [], ""
    if not shutil.which(cfg.nuclei_path) and not Path(cfg.nuclei_path).exists():
        return [], f"nuclei not found: {cfg.nuclei_path}"
    templates = templates or [cfg.poc_dir]
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("\n".join(targets) + "\n")
        target_file = f.name
    try:
        cmd = [cfg.nuclei_path, "-silent", "-jsonl", "-list", target_file, "-c", str(cfg.nuclei_concurrency), "-bs", str(cfg.nuclei_host_concurrency), "-timeout", str(cfg.nuclei_timeout), "-retries", "1"]
        for template in templates:
            cmd += ["-t", template]
        cmd += shlex.split(cfg.nuclei_args)
        rc, out, err, timed_out = run_process(cmd, timeout)
        if timed_out:
            return [], "nuclei timeout"
        ids = []
        for line in out.splitlines():
            with suppress(json.JSONDecodeError):
                item = json.loads(line)
                ids.append(str(item.get("template-id") or item.get("templateID") or item.get("template_id") or ""))
                continue
            if line.strip():
                ids.append(line.split()[0].strip("[]"))
        return unique_sorted(ids), "" if rc == 0 else (err.strip() or f"nuclei exited {rc}")
    finally:
        with suppress(FileNotFoundError):
            os.unlink(target_file)


def nuclei_targets(host: str, assets: list[Asset]) -> list[str]:
    seen: set[str] = set()
    for asset in assets:
        if asset.url:
            seen.add(asset.url)
        elif asset.is_web:
            seen.add(build_url(asset))
        elif asset.port:
            seen.add(join_host_port(asset.target, asset.port))
    return sorted(seen or {host})


def build_url(asset: Asset) -> str:
    scheme = asset.protocol if asset.protocol in {"http", "https"} else asset.service
    if scheme not in {"http", "https"}:
        scheme = "http"
    return f"{scheme}://{join_host_port(asset.target, asset.port)}"


def join_host_port(host: str, port: int) -> str:
    if not host or not port or "://" in host:
        return host
    if re.search(r":\d+$", host) and host.count(":") <= 1:
        return host
    return f"[{host.strip('[]')}]:{port}" if ":" in host else f"{host}:{port}"


def run_process(cmd: list[str], timeout: int) -> tuple[int, str, str, bool]:
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        out, err = proc.communicate()
        return proc.returncode or -9, out, err, True


def run_scan_cli(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="vulnscan-wrapper scan")
    p.add_argument("--namespace", "-namespace", required=True)
    p.add_argument("--ips", "-ips", required=True)
    p.add_argument("--out", "-out", default="scan-result.json")
    p.add_argument("--timeout", "-timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    p.add_argument("--workers", "-workers", type=int, default=6)
    p.add_argument("--total-timeout", "-total-timeout", type=int, default=1800)
    args = p.parse_args(argv)
    if not valid_namespace(args.namespace):
        p.error("namespace is required")
    hosts = normalize_hosts(args.ips.split(","))
    if not hosts:
        p.error("ips is required")
    cfg = load_config()
    workers = max(1, min(args.workers, len(hosts)))
    deadline = time.monotonic() + args.total_timeout if args.total_timeout > 0 else float("inf")
    result_hosts: list[dict[str, Any]] = [{"ip": h, "assets": [], "vulnerabilities": 0, "vulnerability_ids": []} for h in hosts]
    def one(index_ip: tuple[int, str]) -> tuple[int, dict[str, Any]]:
        index, ip = index_ip
        if time.monotonic() >= deadline:
            return index, {"ip": ip, "assets": [], "vulnerabilities": 0, "vulnerability_ids": [], "error": "total timeout"}
        data, err = scan_host(cfg, args.namespace.strip(), ip, min(args.timeout, remaining(deadline)))
        ids = unique_sorted(data.get("vulnerability_ids", []))
        return index, strip_none({"ip": ip, "assets": [a.to_dict() for a in data.get("assets", [])], "vulnerabilities": len(ids), "vulnerability_ids": ids, "error": err or None})
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for index, item in ex.map(one, enumerate(hosts)):
            result_hosts[index] = item
    Path(args.out).write_text(json.dumps({"namespace": args.namespace.strip(), "hosts": result_hosts}, ensure_ascii=False, indent=2) + "\n")
    return 0


def run_scan_child(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="vulnscan-wrapper __scan_host")
    p.add_argument("--poc-dir", required=True); p.add_argument("--fscan-path", default="fscan"); p.add_argument("--nuclei-path", default="nuclei")
    p.add_argument("--fscan-threads", type=int, default=256); p.add_argument("--fscan-timeout", type=int, default=3); p.add_argument("--fscan-ports", default="")
    p.add_argument("--nuclei-concurrency", type=int, default=25); p.add_argument("--nuclei-host-concurrency", type=int, default=1)
    p.add_argument("--nuclei-timeout", type=int, default=5); p.add_argument("--http-fingerprint-timeout", type=int, default=2)
    p.add_argument("--fscan-args", default=""); p.add_argument("--nuclei-args", default=""); p.add_argument("--target", required=True)
    args = p.parse_args(argv)
    cfg = Config(poc_dir=args.poc_dir, fscan_path=args.fscan_path, nuclei_path=args.nuclei_path, fscan_threads=args.fscan_threads,
                 fscan_timeout=args.fscan_timeout, fscan_ports=parse_port_list(args.fscan_ports),
                 nuclei_concurrency=args.nuclei_concurrency, nuclei_host_concurrency=args.nuclei_host_concurrency,
                 nuclei_timeout=args.nuclei_timeout, http_fingerprint_timeout=args.http_fingerprint_timeout,
                 fscan_args=args.fscan_args, nuclei_args=args.nuclei_args).normalized()
    data, err = scan_direct(cfg, args.target, DEFAULT_TIMEOUT_SECONDS)
    print(json.dumps(strip_none({"vulnerability_ids": data.get("vulnerability_ids", []), "assets": [a.to_dict() for a in data.get("assets", [])], "error": err or None}), ensure_ascii=False))
    return 0


def make_celery_app():
    try:
        from celery import Celery
    except Exception:
        return None
    broker = first_env("VST_CELERY_BROKER", "CELERY_BROKER_URL") or Config.celery_broker
    backend = first_env("VST_CELERY_BACKEND", "CELERY_RESULT_BACKEND") or Config.celery_backend
    app = Celery("vulnscan_tool", broker=broker, backend=backend)

    @app.task(name="vulnscan.scan_host")
    def celery_scan_host(namespace: str, ip: str, timeout: int, cfg_data: dict[str, Any]) -> dict[str, Any]:
        cfg = Config.from_dict(cfg_data)
        store = Store(cfg.db_path)
        try:
            data, err = scan_host(cfg, namespace, ip, timeout)
            if err == "scan timeout":
                store.timeout_host(namespace, ip)
            else:
                store.complete_host(namespace, ip, data.get("vulnerability_ids", []), data.get("assets", []), err)
            return {"namespace": namespace, "ip": ip, "error": err}
        finally:
            store.close()
    return app


celery_app = make_celery_app()


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"-h", "--help", "help"}:
        print("Usage:\n  vulnscan-wrapper                 start HTTP service\n  vulnscan-wrapper scan [flags]    scan namespace IPs and write JSON\n  vulnscan-wrapper __scan_host      internal netns worker")
        return 0
    if argv and argv[0] == "scan":
        return run_scan_cli(argv[1:])
    if argv and argv[0] == "__scan_host":
        return run_scan_child(argv[1:])
    if argv and argv[0] == "serve":
        argv.pop(0)
    if argv:
        print(f"unknown command: {argv[0]}", file=sys.stderr)
        return 2
    serve(load_config())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
