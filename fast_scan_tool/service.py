from __future__ import annotations

import ipaddress
import json
import logging
import queue
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import DEFAULT_TIMEOUT_SECONDS, Config
from .models import normalize_hosts, strip_none, valid_namespace
from .scanner import scan_host
from .store import Store
from .worker import celery_app


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
                self.write_error(403, "local requests only")
                return
            if self.path != "/scan":
                self.write_error(404, "not found")
                return
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
                self.write_error(403, "local requests only")
                return
            parsed = urllib.parse.urlparse(self.path)
            namespace = ""
            if parsed.path == "/scan":
                namespace = urllib.parse.parse_qs(parsed.query).get("namespace", [""])[0].strip()
            elif parsed.path.startswith("/scan/"):
                namespace = parsed.path.removeprefix("/scan/").strip("/")
            if not namespace:
                self.write_error(400, "missing namespace")
                return
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
