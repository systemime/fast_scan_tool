import sqlite3
import tempfile
import unittest
from pathlib import Path

import fast_scan_tool as v
import fast_scan_tool.scanner as scanner


class FastScanToolTest(unittest.TestCase):
    def test_store_syncs_hosts_and_results(self):
        with tempfile.TemporaryDirectory() as d:
            store = v.Store(str(Path(d) / "tasks.db"))
            try:
                first = store.upsert_task("ns1", ["10.0.0.2", "10.0.0.1"], 10)
                self.assertEqual(first["host_count"], 2)
                self.assertEqual(first["added"], ["10.0.0.1", "10.0.0.2"])
                second = store.upsert_task("ns1", ["10.0.0.2", "10.0.0.3"], 20)
                self.assertEqual(second["added"], ["10.0.0.3"])
                self.assertEqual(second["removed"], ["10.0.0.1"])
                timeout, ok = store.begin_host("ns1", "10.0.0.2")
                self.assertTrue(ok)
                self.assertEqual(timeout, 20)
                store.complete_host("ns1", "10.0.0.2", ["cve-2", "cve-1", "cve-1"], [v.Asset(type="SERVICE", target="10.0.0.2", port=80, url="http://10.0.0.2", fingerprints=["nginx", "nginx"])])
                task = store.get_task("ns1")
                host = next(h for h in task["hosts"] if h["ip"] == "10.0.0.2")
                self.assertEqual(host["status"], v.STATUS_DONE)
                self.assertEqual(host["vulnerability_ids"], ["cve-1", "cve-2"])
                self.assertEqual(host["assets"][0]["fingerprints"], ["nginx"])
            finally:
                store.close()

    def test_store_migrates_legacy_columns(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "tasks.db"
            db = sqlite3.connect(path)
            db.executescript(
                """
CREATE TABLE namespaces (
  namespace TEXT PRIMARY KEY,
  timeout_seconds INTEGER NOT NULL,
  host_count INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE hosts (
  namespace TEXT NOT NULL,
  ip TEXT NOT NULL,
  status TEXT NOT NULL,
  timeout_seconds INTEGER NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  vulnerabilities INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (namespace, ip)
);
INSERT INTO namespaces VALUES ('ns1', 10, 1, '2026-01-01T00:00:00+00:00');
INSERT INTO hosts VALUES ('ns1', '10.0.0.1', '未开始', 10, NULL, NULL, 0, '', '2026-01-01T00:00:00+00:00');
"""
            )
            db.close()

            store = v.Store(str(path))
            try:
                columns = {row["name"] for row in store.db.execute("PRAGMA table_info(hosts)")}
                self.assertTrue({"vulnerability_ids", "assets"} <= columns)
                host = store.get_task("ns1")["hosts"][0]
                self.assertEqual(host["status"], v.STATUS_PENDING)
                self.assertEqual(host["vulnerability_ids"], [])
                self.assertEqual(host["assets"], [])
                self.assertEqual(store.begin_host("ns1", "10.0.0.1"), (10, True))
                store.complete_host("ns1", "10.0.0.1", ["cve-1"], [])
            finally:
                store.close()

            reopened = v.Store(str(path))
            try:
                self.assertEqual(reopened.get_task("ns1")["hosts"][0]["vulnerability_ids"], ["cve-1"])
            finally:
                reopened.close()

    def test_port_list_and_targets(self):
        self.assertEqual(v.parse_port_list("443,80,443"), [80, 443])
        with self.assertRaises(ValueError):
            v.parse_port_list("0")
        assets = [
            v.Asset(type="SERVICE", target="10.0.0.2", port=22, service="ssh"),
            v.Asset(type="SERVICE", target="10.0.0.2", port=8443, service="https", protocol="https", is_web=True),
        ]
        self.assertEqual(v.nuclei_targets("10.0.0.2", assets), ["10.0.0.2:22", "https://10.0.0.2:8443"])

    def test_child_command_uses_outer_binary_when_compiled(self):
        old_argv = scanner.sys.argv[:]
        try:
            scanner.__dict__["__compiled__"] = True
            scanner.sys.argv = ["/tmp/vulnscan-wrapper"]
            self.assertEqual(v.child_command(), ["/tmp/vulnscan-wrapper"])
        finally:
            scanner.__dict__.pop("__compiled__", None)
            scanner.sys.argv = old_argv

    def test_run_fscan_does_not_parse_stderr_usage_as_assets(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "fscan"
            fake.write_text("#!/bin/sh\necho '192.168.1.1:22 ssh' >&2\nexit 2\n")
            fake.chmod(0o700)
            assets, err = v.run_fscan(v.Config(fscan_path=str(fake)), "192.168.1.1", 5)
            self.assertEqual(assets, [])
            self.assertIn("192.168.1.1:22", err)

    def test_fscan_json_and_http_fingerprint_parsing(self):
        assets = v.parse_fscan_line('{"target":"10.0.0.5","details":{"port":8080,"service":"http","title":"Admin","fingerprints":["nginx","nginx"]}}')
        self.assertEqual(assets[0].url, "http://10.0.0.5:8080")
        self.assertIn("jenkins", v.http_fingerprint_values({}, b"<html><title>Jenkins</title></html>"))


if __name__ == "__main__":
    unittest.main()
