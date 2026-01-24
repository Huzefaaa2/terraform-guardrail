from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

DEFAULT_POLICY_REGISTRY_URL = "http://localhost:8081"


class PolicyRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class BundleVerification:
    public_key: str | None = None
    public_key_url: str | None = None
    public_key_path: str | None = None
    key_id: str | None = None
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_key": self.public_key,
            "public_key_url": self.public_key_url,
            "public_key_path": self.public_key_path,
            "key_id": self.key_id,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    title: str
    description: str
    version: str | None
    url: str
    sha256: str | None
    entrypoint: str | None = None
    verification: BundleVerification | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.bundle_id,
            "title": self.title,
            "description": self.description,
            "version": self.version,
            "url": self.url,
            "sha256": self.sha256,
            "entrypoint": self.entrypoint,
        }
        if self.verification:
            payload["verification"] = self.verification.to_dict()
        return payload


def get_policy_registry_url(override: str | None = None) -> str:
    return override or os.getenv("GUARDRAIL_POLICY_REGISTRY_URL", DEFAULT_POLICY_REGISTRY_URL)


def fetch_registry_index(registry_url: str | None = None) -> dict[str, Any]:
    base_url = get_policy_registry_url(registry_url).rstrip("/") + "/"
    response = requests.get(urljoin(base_url, "registry.json"), timeout=10)
    if response.status_code != 200:
        raise PolicyRegistryError(f"Registry lookup failed: {response.status_code}")
    return response.json()


def _resolve_bundle_url(base_url: str, bundle_url: str) -> str:
    if bundle_url.startswith("http://") or bundle_url.startswith("https://"):
        return bundle_url
    return urljoin(base_url, bundle_url.lstrip("/"))


def list_policy_bundles(registry_url: str | None = None) -> list[PolicyBundle]:
    base_url = get_policy_registry_url(registry_url).rstrip("/") + "/"
    data = fetch_registry_index(base_url)
    bundles = data.get("bundles", [])
    if not isinstance(bundles, list):
        raise PolicyRegistryError("Registry bundles must be a list.")

    parsed: list[PolicyBundle] = []
    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        bundle_id = bundle.get("id")
        title = bundle.get("title")
        description = bundle.get("description")
        entrypoint = bundle.get("entrypoint")
        selected_version = _select_bundle_version(bundle)
        url = selected_version.get("url") or bundle.get("url")
        if not all([bundle_id, title, description, url]):
            continue
        verification = _parse_verification(bundle.get("verification"))
        parsed.append(
            PolicyBundle(
                bundle_id=bundle_id,
                title=title,
                description=description,
                version=selected_version.get("version") or bundle.get("version"),
                url=_resolve_bundle_url(base_url, url),
                sha256=selected_version.get("sha256") or bundle.get("sha256"),
                entrypoint=entrypoint,
                verification=verification,
            )
        )
    return parsed


def get_policy_bundle(bundle_id: str, registry_url: str | None = None) -> PolicyBundle:
    bundles = list_policy_bundles(registry_url)
    for bundle in bundles:
        if bundle.bundle_id == bundle_id:
            return bundle
    raise PolicyRegistryError(f"Bundle '{bundle_id}' not found.")


def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in tar.getmembers():
        member_path = (destination / member.name).resolve()
        if not str(member_path).startswith(str(destination)):
            raise PolicyRegistryError("Unsafe path detected in bundle.")
    tar.extractall(destination)


def _select_bundle_version(bundle: dict[str, Any]) -> dict[str, Any]:
    versions = bundle.get("versions")
    if not isinstance(versions, list) or not versions:
        return {}
    latest = bundle.get("latest")
    if latest:
        for entry in versions:
            if isinstance(entry, dict) and entry.get("version") == latest:
                return entry
    for entry in versions:
        if isinstance(entry, dict):
            return entry
    return {}


def _parse_verification(data: Any) -> BundleVerification | None:
    if not isinstance(data, dict):
        return None
    return BundleVerification(
        public_key=data.get("public_key"),
        public_key_url=data.get("public_key_url"),
        public_key_path=data.get("public_key_path"),
        key_id=data.get("key_id"),
        scope=data.get("scope"),
    )


def _load_verification_key(verification: BundleVerification) -> str:
    if verification.public_key:
        return verification.public_key
    if verification.public_key_path:
        key_path = Path(verification.public_key_path)
        if not key_path.exists():
            raise PolicyRegistryError("Verification key path not found.")
        return key_path.read_text(encoding="utf-8")
    if verification.public_key_url:
        response = requests.get(verification.public_key_url, timeout=10)
        if response.status_code != 200:
            raise PolicyRegistryError("Failed to download verification key.")
        return response.text
    raise PolicyRegistryError("Verification key is missing.")


def _verify_bundle_signature(bundle: PolicyBundle, bundle_path: Path) -> Path:
    if not bundle.verification:
        return bundle_path

    opa_path = shutil.which("opa")
    if not opa_path:
        raise PolicyRegistryError("OPA CLI not found for bundle signature verification.")

    key_text = _load_verification_key(bundle.verification)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        key_path = tmp_dir_path / "bundle.pub"
        key_path.write_text(key_text, encoding="utf-8")

        verified_path = tmp_dir_path / "verified.tar.gz"
        cmd = [
            opa_path,
            "build",
            "--bundle",
            str(bundle_path),
            "--verification-key",
            str(key_path),
            "--output",
            str(verified_path),
        ]
        if bundle.verification.key_id:
            cmd.extend(["--verification-key-id", bundle.verification.key_id])
        if bundle.verification.scope:
            cmd.extend(["--scope", bundle.verification.scope])

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise PolicyRegistryError(
                f"Bundle signature verification failed: {result.stderr.strip()}"
            )

        verified_path_final = bundle_path.parent / f"{bundle.bundle_id}-verified.tar.gz"
        shutil.copy(verified_path, verified_path_final)
        return verified_path_final


def download_bundle(bundle: PolicyBundle, destination: Path) -> Path:
    response = requests.get(bundle.url, timeout=30)
    if response.status_code != 200:
        raise PolicyRegistryError(f"Bundle download failed: {response.status_code}")
    content = response.content

    if bundle.sha256:
        digest = hashlib.sha256(content).hexdigest()
        if digest.lower() != bundle.sha256.lower():
            raise PolicyRegistryError("Bundle checksum mismatch.")

    destination.mkdir(parents=True, exist_ok=True)
    bundle_dir = destination / bundle.bundle_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_bundle_path = Path(tmp_dir) / f"{bundle.bundle_id}.tar.gz"
        tmp_bundle_path.write_bytes(content)
        verified_path = _verify_bundle_signature(bundle, tmp_bundle_path)
        bundle_bytes = verified_path.read_bytes()

    with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz") as tar:
        _safe_extract(tar, bundle_dir)

    return bundle_dir
