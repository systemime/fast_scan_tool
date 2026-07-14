from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .config import DEFAULT_TIMEOUT_SECONDS, Config, load_config, parse_port_list
from .models import normalize_hosts, strip_none, unique_sorted, valid_namespace
from .scanner import remaining, scan_direct, scan_host
from .service import serve


def run_scan_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vulnscan-wrapper scan")
    parser.add_argument("--namespace", "-namespace", required=True)
    parser.add_argument("--ips", "-ips", required=True)
    parser.add_argument("--out", "-out", default="scan-result.json")
    parser.add_argument("--timeout", "-timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--workers", "-workers", type=int, default=6)
    parser.add_argument("--total-timeout", "-total-timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    if not valid_namespace(args.namespace):
        parser.error("namespace is required")
    hosts = normalize_hosts(args.ips.split(","))
    if not hosts:
        parser.error("ips is required")
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

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, item in executor.map(one, enumerate(hosts)):
            result_hosts[index] = item
    Path(args.out).write_text(json.dumps({"namespace": args.namespace.strip(), "hosts": result_hosts}, ensure_ascii=False, indent=2) + "\n")
    return 0


def run_scan_child(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vulnscan-wrapper __scan_host")
    parser.add_argument("--poc-dir", required=True)
    parser.add_argument("--fscan-path", default="fscan")
    parser.add_argument("--nuclei-path", default="nuclei")
    parser.add_argument("--fscan-threads", type=int, default=256)
    parser.add_argument("--fscan-timeout", type=int, default=3)
    parser.add_argument("--fscan-ports", default="")
    parser.add_argument("--nuclei-concurrency", type=int, default=25)
    parser.add_argument("--nuclei-host-concurrency", type=int, default=1)
    parser.add_argument("--nuclei-timeout", type=int, default=5)
    parser.add_argument("--http-fingerprint-timeout", type=int, default=2)
    parser.add_argument("--fscan-args", default="")
    parser.add_argument("--nuclei-args", default="")
    parser.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    cfg = Config(
        poc_dir=args.poc_dir,
        fscan_path=args.fscan_path,
        nuclei_path=args.nuclei_path,
        fscan_threads=args.fscan_threads,
        fscan_timeout=args.fscan_timeout,
        fscan_ports=parse_port_list(args.fscan_ports),
        nuclei_concurrency=args.nuclei_concurrency,
        nuclei_host_concurrency=args.nuclei_host_concurrency,
        nuclei_timeout=args.nuclei_timeout,
        http_fingerprint_timeout=args.http_fingerprint_timeout,
        fscan_args=args.fscan_args,
        nuclei_args=args.nuclei_args,
    ).normalized()
    data, err = scan_direct(cfg, args.target, DEFAULT_TIMEOUT_SECONDS)
    print(json.dumps(strip_none({"vulnerability_ids": data.get("vulnerability_ids", []), "assets": [a.to_dict() for a in data.get("assets", [])], "error": err or None}), ensure_ascii=False))
    return 0


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
