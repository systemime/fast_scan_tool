import tempfile
import unittest
from pathlib import Path

import vulnscan_tool as v


class VulnscanToolTest(unittest.TestCase):
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
        old_argv = v.sys.argv[:]
        try:
            v.__dict__["__compiled__"] = True
            v.sys.argv = ["/tmp/vulnscan-wrapper"]
            self.assertEqual(v.child_command(), ["/tmp/vulnscan-wrapper"])
        finally:
            v.__dict__.pop("__compiled__", None)
            v.sys.argv = old_argv

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
