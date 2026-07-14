from __future__ import annotations

from typing import Any

from .config import Config, first_env
from .scanner import scan_host
from .store import Store


def make_celery_app():
    try:
        from celery import Celery
    except Exception:
        return None
    broker = first_env("VST_CELERY_BROKER", "CELERY_BROKER_URL") or Config.celery_broker
    backend = first_env("VST_CELERY_BACKEND", "CELERY_RESULT_BACKEND") or Config.celery_backend
    app = Celery("fast_scan_tool", broker=broker, backend=backend)

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
