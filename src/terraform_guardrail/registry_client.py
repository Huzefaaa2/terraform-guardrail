from __future__ import annotations

from typing import Any

import requests

PROVIDER_MAP = {
    "aws": ("hashicorp", "aws"),
    "azure": ("hashicorp", "azurerm"),
    "azurerm": ("hashicorp", "azurerm"),
}


class RegistryError(RuntimeError):
    pass


def get_provider_metadata(provider: str) -> dict[str, Any]:
    if provider not in PROVIDER_MAP:
        raise RegistryError(f"Unsupported provider '{provider}'.")

    namespace, name = PROVIDER_MAP[provider]
    url = f"https://registry.terraform.io/v1/providers/{namespace}/{name}"
    response = requests.get(url, timeout=10)
    if response.status_code != 200:
        raise RegistryError(f"Registry lookup failed: {response.status_code}")
    data = response.json()
    return {
        "namespace": namespace,
        "name": name,
        "latest_version": data.get("version"),
        "source": data.get("source"),
        "provider_url": data.get("provider"),
        "tagline": data.get("tagline"),
    }
