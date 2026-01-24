from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.registry_client import RegistryError, get_provider_metadata
from terraform_guardrail.scanner.scan import scan_path


class ScanRequest(BaseModel):
    path: str
    state_path: str | None = None
    use_schema: bool = False


class ProviderRequest(BaseModel):
    provider: str


class SnippetRequest(BaseModel):
    provider: str
    resource: str
    name: str = "example"


def create_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail MCP API", version="0.2.5")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scan")
    def scan(request: ScanRequest) -> dict[str, Any]:
        path = Path(request.path)
        state_path = Path(request.state_path) if request.state_path else None
        try:
            report = scan_path(path, state_path=state_path, use_schema=request.use_schema)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return report.model_dump()

    @app.post("/provider-metadata")
    def provider_metadata(request: ProviderRequest) -> dict[str, Any]:
        try:
            return get_provider_metadata(request.provider)
        except RegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/generate-snippet")
    def snippet(request: SnippetRequest) -> dict[str, Any]:
        try:
            snippet = generate_snippet(request.provider, request.resource, request.name)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"language": snippet.language, "content": snippet.content}

    return app
