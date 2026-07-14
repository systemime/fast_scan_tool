from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Asset, normalize_hosts, strip_none, unique_assets, unique_sorted


STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "completed"
STATUS_TIMEOUT = "timeout"


def now_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str | None) -> str | None:
    return value or None


class Store:
    def __init__(self, path: str):
        parent = Path(path).parent
        if parent != Path("."):
            parent.mkdir(parents=True, exist_ok=True)
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
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._ensure_column("hosts", "vulnerability_ids", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column("hosts", "assets", "TEXT NOT NULL DEFAULT '[]'")
            self.db.execute(
                """UPDATE hosts SET status = CASE status
WHEN '未开始' THEN ? WHEN '进行中' THEN ? WHEN '已完成' THEN ? WHEN '超时' THEN ? ELSE status END""",
                (STATUS_PENDING, STATUS_RUNNING, STATUS_DONE, STATUS_TIMEOUT),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in self.db.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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
        result["added"].sort()
        result["removed"].sort()
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
                    jobs.append((row["namespace"], row["ip"]))
                    continue
                if now > started + timedelta(seconds=int(row["timeout_seconds"])):
                    jobs.append((row["namespace"], row["ip"]))
        return jobs
