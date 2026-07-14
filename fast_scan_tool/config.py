from __future__ import annotations

import dataclasses
import json
import math
import os
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 600


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


def first_env(*keys: str) -> str:
    for key in keys:
        if value := os.environ.get(key, "").strip():
            return value
    return ""


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
