from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

DEFAULT_REGISTRY_ROOT = Path("ops/policy-registry")


def _registry_root() -> Path:
    return Path(os.getenv("GUARDRAIL_REGISTRY_DATA_DIR", DEFAULT_REGISTRY_ROOT)).resolve()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Registry file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def create_registry_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail Policy Registry", version="0.2.10")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/bundles")
    def bundles() -> dict[str, Any]:
        try:
            registry = _load_json(_registry_root() / "registry.json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"bundles": registry.get("bundles", [])}

    @app.get("/bundles/{bundle_id}")
    def bundle(bundle_id: str) -> dict[str, Any]:
        registry = _load_json(_registry_root() / "registry.json")
        for entry in registry.get("bundles", []):
            if entry.get("id") == bundle_id:
                return entry
        raise HTTPException(status_code=404, detail="Bundle not found.")

    @app.get("/bundles/{bundle_id}/versions")
    def bundle_versions(bundle_id: str) -> dict[str, Any]:
        registry = _load_json(_registry_root() / "registry.json")
        for entry in registry.get("bundles", []):
            if entry.get("id") == bundle_id:
                return {"versions": entry.get("versions", [])}
        raise HTTPException(status_code=404, detail="Bundle not found.")

    @app.get("/audit")
    def audit_log() -> dict[str, Any]:
        try:
            audit = _load_json(_registry_root() / "audit.json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return audit

    @app.get("/bundles/{bundle_id}/audit")
    def bundle_audit(bundle_id: str) -> dict[str, Any]:
        audit = _load_json(_registry_root() / "audit.json")
        entries = [
            entry for entry in audit.get("events", []) if entry.get("bundle_id") == bundle_id
        ]
        if not entries:
            raise HTTPException(status_code=404, detail="Audit entries not found.")
        return {"events": entries}

    return app
