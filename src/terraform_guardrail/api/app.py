from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel

from terraform_guardrail.generator import generate_snippet
from terraform_guardrail.policy_registry import (
    PolicyRegistryError,
    get_policy_bundle,
    list_policy_bundles,
)
from terraform_guardrail.registry_client import RegistryError, get_provider_metadata
from terraform_guardrail.scanner.scan import scan_path

REQUEST_COUNT = Counter(
    "guardrail_requests_total",
    "Total API requests",
    ["path", "method", "status"],
)
REQUEST_LATENCY = Histogram(
    "guardrail_request_duration_seconds",
    "API request latency in seconds",
    ["path"],
)


class ScanRequest(BaseModel):
    path: str
    state_path: str | None = None
    use_schema: bool = False
    policy_bundle: str | None = None
    policy_registry: str | None = None
    policy_query: str | None = None


class ProviderRequest(BaseModel):
    provider: str


class SnippetRequest(BaseModel):
    provider: str
    resource: str
    name: str = "example"


def create_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail MCP API", version="0.2.10")

    @app.middleware("http")
    async def record_metrics(request, call_next):  # type: ignore[no-untyped-def]
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start
        REQUEST_COUNT.labels(
            request.url.path,
            request.method,
            str(response.status_code),
        ).inc()
        REQUEST_LATENCY.labels(request.url.path).observe(duration)
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/scan")
    def scan(request: ScanRequest) -> dict[str, Any]:
        path = Path(request.path)
        state_path = Path(request.state_path) if request.state_path else None
        try:
            report = scan_path(
                path,
                state_path=state_path,
                use_schema=request.use_schema,
                policy_bundle=request.policy_bundle,
                policy_registry=request.policy_registry,
                policy_query=request.policy_query,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return report.model_dump()

    @app.post("/provider-metadata")
    def provider_metadata(request: ProviderRequest) -> dict[str, Any]:
        try:
            return get_provider_metadata(request.provider)
        except RegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/policy-bundles")
    def policy_bundles() -> dict[str, Any]:
        try:
            bundles = list_policy_bundles()
        except PolicyRegistryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"bundles": [bundle.to_dict() for bundle in bundles]}

    @app.get("/policy-bundles/{bundle_id}")
    def policy_bundle(bundle_id: str) -> dict[str, Any]:
        try:
            bundle = get_policy_bundle(bundle_id)
        except PolicyRegistryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return bundle.to_dict()

    @app.post("/generate-snippet")
    def snippet(request: SnippetRequest) -> dict[str, Any]:
        try:
            snippet = generate_snippet(request.provider, request.resource, request.name)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"language": snippet.language, "content": snippet.content}

    return app
