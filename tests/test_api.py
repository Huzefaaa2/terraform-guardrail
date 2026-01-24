from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from terraform_guardrail.api.app import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "guardrail_requests_total" in response.text


def test_generate_snippet_endpoint() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/generate-snippet",
        json={"provider": "aws", "resource": "aws_s3_bucket", "name": "demo"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["language"] == "hcl"
    assert "aws_s3_bucket" in payload["content"]


def test_provider_metadata_endpoint(monkeypatch) -> None:
    client = TestClient(create_app())

    def fake_metadata(provider: str) -> dict[str, str]:
        assert provider == "aws"
        return {"name": "aws", "latest_version": "1.2.3"}

    monkeypatch.setattr(
        "terraform_guardrail.api.app.get_provider_metadata",
        fake_metadata,
    )

    response = client.post("/provider-metadata", json={"provider": "aws"})
    assert response.status_code == 200
    assert response.json()["latest_version"] == "1.2.3"


def test_scan_endpoint(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable \"db_password\" {
  type      = string
  sensitive = true
}
""",
        encoding="utf-8",
    )

    client = TestClient(create_app())
    response = client.post("/scan", json={"path": str(tf_file)})
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["findings"] >= 1
