from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


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


def unique_sorted(values: list[str]) -> list[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})


def normalize_hosts(hosts: list[str]) -> list[str]:
    return unique_sorted(hosts)


def valid_namespace(namespace: str) -> bool:
    return bool(namespace and namespace not in {".", ".."} and "/" not in namespace and "\x00" not in namespace)


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
