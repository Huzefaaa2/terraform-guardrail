from __future__ import annotations

import json

from fastapi.testclient import TestClient

from terraform_guardrail.registry_api import create_registry_app


def test_registry_api_endpoints(monkeypatch, tmp_path) -> None:
    registry = {
        "bundles": [
            {
                "id": "baseline",
                "title": "Baseline",
                "versions": [{"version": "0.1.0"}],
            }
        ]
    }
    audit = {"events": [{"bundle_id": "baseline"}]}

    (tmp_path / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
    (tmp_path / "audit.json").write_text(json.dumps(audit), encoding="utf-8")

    monkeypatch.setenv("GUARDRAIL_REGISTRY_DATA_DIR", str(tmp_path))
    client = TestClient(create_registry_app())

    assert client.get("/bundles").status_code == 200
    assert client.get("/bundles/baseline").status_code == 200
    assert client.get("/bundles/baseline/versions").status_code == 200
    assert client.get("/audit").status_code == 200
    assert client.get("/bundles/baseline/audit").status_code == 200
