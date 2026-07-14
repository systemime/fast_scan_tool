from __future__ import annotations

import dataclasses
import html
import json
import logging
import os
import re
import shlex
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any

from .config import Config, format_port_list
from .models import Asset, unique_assets, unique_sorted


def scan_host(cfg: Config, namespace: str, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    if namespace:
        if sys.platform != "linux":
            return {}, f"network namespace {namespace!r} requires linux"
        return scan_host_process(cfg, namespace, ip, timeout)
    return scan_direct(cfg, ip, timeout)


def scan_host_process(cfg: Config, namespace: str, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    cmd = [
        "ip", "netns", "exec", namespace, *child_command(), "__scan_host",
        "--poc-dir", cfg.poc_dir, "--fscan-path", cfg.fscan_path, "--nuclei-path", cfg.nuclei_path,
        "--fscan-threads", str(cfg.fscan_threads), "--fscan-timeout", str(cfg.fscan_timeout),
        "--fscan-ports", format_port_list(cfg.fscan_ports),
        "--nuclei-concurrency", str(cfg.nuclei_concurrency), "--nuclei-host-concurrency", str(cfg.nuclei_host_concurrency),
        "--nuclei-timeout", str(cfg.nuclei_timeout), "--http-fingerprint-timeout", str(cfg.http_fingerprint_timeout),
        "--fscan-args", cfg.fscan_args, "--nuclei-args", cfg.nuclei_args, "--target", ip,
    ]
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
    return [sys.executable, "-m", "fast_scan_tool"]


def scan_direct(cfg: Config, ip: str, timeout: int) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + max(1, timeout)
    errors: list[str] = []
    assets, err = run_fscan(cfg, ip, remaining(deadline))
    if err:
        errors.append(err)
    assets = enrich_http_fingerprints(cfg, assets, remaining(deadline))
    logging.info("nuclei poc_dir=%s", cfg.poc_dir)
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
    match = re.search(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9_.:-]+):(?P<port>\d{1,5})\s*(?P<svc>[a-zA-Z0-9_-]+)?", line)
    if match:
        port = int(match.group("port"))
        service = (match.group("svc") or "").lower()
        assets.append(Asset(type="SERVICE", target=match.group("host"), port=port, service=service, protocol=service, is_web=service in {"http", "https"}))
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
    match = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", match.group(1).decode("utf-8", "ignore")).strip()) if match else ""


def scan_nuclei_targets(cfg: Config, targets: list[str], templates: list[str], timeout: int) -> tuple[list[str], str]:
    if not targets:
        return [], ""
    if not shutil.which(cfg.nuclei_path) and not Path(cfg.nuclei_path).exists():
        return [], f"nuclei not found: {cfg.nuclei_path}"
    templates = templates or [cfg.poc_dir]
    with tempfile.NamedTemporaryFile("w", delete=False) as target_stream:
        target_stream.write("\n".join(targets) + "\n")
        target_file = target_stream.name
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
    kwargs: dict[str, Any] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True}
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
