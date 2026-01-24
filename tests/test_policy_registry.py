from __future__ import annotations

import io
import tarfile
from typing import Any

import pytest

from terraform_guardrail.policy_registry import (
    PolicyBundle,
    PolicyRegistryError,
    download_bundle,
    list_policy_bundles,
)


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        json_data: dict[str, Any] | None = None,
        content: bytes = b"",
    ):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.content = content

    def json(self) -> dict[str, Any]:
        return self._json_data


def test_list_policy_bundles(monkeypatch) -> None:
    def fake_get(url: str, timeout: int = 10) -> FakeResponse:
        assert url == "http://registry.local/registry.json"
        return FakeResponse(
            200,
            json_data={
                "bundles": [
                    {
                        "id": "baseline",
                        "title": "Baseline",
                        "description": "Test bundle",
                        "version": "0.1.0",
                        "url": "/bundles/baseline.tar.gz",
                        "sha256": "abc",
                    }
                ]
            },
        )

    monkeypatch.setattr("terraform_guardrail.policy_registry.requests.get", fake_get)
    bundles = list_policy_bundles("http://registry.local")
    assert bundles[0].url == "http://registry.local/bundles/baseline.tar.gz"


def test_download_bundle(monkeypatch, tmp_path) -> None:
    bundle_bytes = io.BytesIO()
    with tarfile.open(fileobj=bundle_bytes, mode="w:gz") as tar:
        info = tarfile.TarInfo(".manifest")
        manifest_bytes = b'{"revision":"0.1.0","roots":["policies"]}'
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))

    content = bundle_bytes.getvalue()

    def fake_get(url: str, timeout: int = 30) -> FakeResponse:
        return FakeResponse(200, content=content)

    monkeypatch.setattr("terraform_guardrail.policy_registry.requests.get", fake_get)
    bundle = PolicyBundle(
        bundle_id="baseline",
        title="Baseline",
        description="Test bundle",
        version="0.1.0",
        url="http://registry.local/bundles/baseline.tar.gz",
        sha256=None,
    )
    extracted = download_bundle(bundle, tmp_path)
    assert (extracted / ".manifest").exists()


def test_download_bundle_checksum_mismatch(monkeypatch, tmp_path) -> None:
    def fake_get(url: str, timeout: int = 30) -> FakeResponse:
        return FakeResponse(200, content=b"invalid")

    monkeypatch.setattr("terraform_guardrail.policy_registry.requests.get", fake_get)
    bundle = PolicyBundle(
        bundle_id="baseline",
        title="Baseline",
        description="Test bundle",
        version="0.1.0",
        url="http://registry.local/bundles/baseline.tar.gz",
        sha256="deadbeef",
    )
    with pytest.raises(PolicyRegistryError):
        download_bundle(bundle, tmp_path)
