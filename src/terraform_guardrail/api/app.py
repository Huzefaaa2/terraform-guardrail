from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel

from terraform_guardrail.enterprise import (
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    EvaluationContext,
    GroupPolicyBinding,
    check_drift,
    ensure_policy_pack_installed,
    evaluate_enterprise,
    export_evidence,
    get_builtin_policy_pack,
    install_policy_pack,
    list_builtin_policy_packs,
    preview_policy,
    resolve_policy_set,
    run_drift_gate,
)
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
    policy_layers: list[str] | None = None
    policy_base: str | None = None
    policy_env: str | None = None
    policy_app: str | None = None
    policy_registry: str | None = None
    policy_query: str | None = None


class ProviderRequest(BaseModel):
    provider: str


class SnippetRequest(BaseModel):
    provider: str
    resource: str
    name: str = "example"


class PolicyVersionRequest(BaseModel):
    version: str
    rule_body: str = ""
    actor: str = "system"


class PolicyApprovalRequest(BaseModel):
    actor: str = "system"
    comment: str | None = None


class BaselineVersionRequest(BaseModel):
    version: str
    policy_ids: list[str] | None = None
    actor: str = "system"


class PolicyPreviewRequest(BaseModel):
    path: str
    state_path: str | None = None
    actor: str = "system"


class EvaluateRequest(BaseModel):
    path: str
    state_path: str | None = None
    provider: str | None = None
    policy_set: str | None = None
    baseline: str | None = None
    context: dict[str, Any] | None = None
    fail_on: str | None = None
    actor: str = "system"


class ServiceEvaluateRequest(BaseModel):
    path: str
    state_path: str | None = None
    request_id: str | None = None
    provider: str | None = None
    policy_pack: str | None = None
    baseline: str | None = None
    context: dict[str, Any] | None = None
    fail_on: str | None = None
    evidence_format: str | None = "json"
    actor: str = "service"
    callback_url: str | None = None


class DriftCheckRequest(BaseModel):
    path: str
    state_path: str | None = None
    snapshot_id: str = "default"
    update_snapshot: bool = False
    actor: str = "system"


class EvidenceExportRequest(BaseModel):
    result_id: str
    format: str = "json"
    actor: str = "system"


class DriftGateRequest(BaseModel):
    path: str
    state_path: str | None = None
    snapshot_id: str = "default"
    provider: str | None = None
    policy_set: str | None = None
    baseline: str | None = None
    context: dict[str, Any] | None = None
    fail_on: str | None = None
    update_snapshot: bool = False
    create_snapshot: bool = True
    evidence_format: str | None = None
    actor: str = "system"


class BindingResolveRequest(BaseModel):
    org: str | None = None
    group: str | None = None
    repo: str | None = None
    baseline: str | None = None


class PolicyPackInstallRequest(BaseModel):
    actor: str = "system"
    approve: bool = True
    create_baseline: bool = True


def create_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail MCP (TerraGuard) API", version="2.0.0")

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
                policy_layers=request.policy_layers,
                policy_base=request.policy_base,
                policy_env=request.policy_env,
                policy_app=request.policy_app,
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

    @app.get("/packs")
    def packs() -> dict[str, Any]:
        return {
            "packs": [
                pack.model_dump(mode="json", exclude={"policies"})
                for pack in list_builtin_policy_packs()
            ]
        }

    @app.get("/packs/{pack_id}")
    def pack(pack_id: str) -> dict[str, Any]:
        try:
            return get_builtin_policy_pack(pack_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/packs/{pack_id}/install")
    def install_pack(pack_id: str, request: PolicyPackInstallRequest) -> dict[str, Any]:
        try:
            result = install_policy_pack(
                pack_id,
                actor=request.actor,
                approve=request.approve,
                create_baseline=request.create_baseline,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/generate-snippet")
    def snippet(request: SnippetRequest) -> dict[str, Any]:
        try:
            snippet = generate_snippet(request.provider, request.resource, request.name)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"language": snippet.language, "content": snippet.content}

    @app.post("/policies")
    def create_policy(policy: EnterprisePolicy) -> dict[str, Any]:
        try:
            return EnterpriseStore().save_policy(policy).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/policies")
    def policies(scope: str | None = None) -> dict[str, Any]:
        items = EnterpriseStore().list_policies()
        if scope:
            items = [policy for policy in items if policy.scope == scope]
        return {"policies": [policy.model_dump(mode="json") for policy in items]}

    @app.get("/policies/{policy_id}")
    def policy(policy_id: str) -> dict[str, Any]:
        try:
            return EnterpriseStore().get_policy(policy_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/policies/{policy_id}")
    def update_policy(policy_id: str, policy: EnterprisePolicy) -> dict[str, Any]:
        if policy.id != policy_id:
            policy.id = policy_id
        try:
            return EnterpriseStore().save_policy(policy).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/policies/{policy_id}/versions")
    def create_policy_version(policy_id: str, request: PolicyVersionRequest) -> dict[str, Any]:
        try:
            version = EnterpriseStore().add_policy_version(
                policy_id=policy_id,
                version=request.version,
                rule_body=request.rule_body,
                actor=request.actor,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return version.model_dump(mode="json")

    @app.get("/policies/{policy_id}/versions")
    def policy_versions(policy_id: str) -> dict[str, Any]:
        versions = EnterpriseStore().list_policy_versions(policy_id)
        return {"versions": [version.model_dump(mode="json") for version in versions]}

    @app.post("/policies/{policy_id}/approve")
    def approve_policy(policy_id: str, request: PolicyApprovalRequest) -> dict[str, Any]:
        try:
            approval = EnterpriseStore().approve_policy(
                policy_id=policy_id,
                actor=request.actor,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return approval.model_dump(mode="json")

    @app.post("/policies/{policy_id}/preview")
    def preview_enterprise_policy(
        policy_id: str,
        request: PolicyPreviewRequest,
    ) -> dict[str, Any]:
        try:
            result = preview_policy(
                policy_id=policy_id,
                path=request.path,
                state_path=request.state_path,
                actor=request.actor,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/baselines")
    def create_baseline(baseline: Baseline) -> dict[str, Any]:
        try:
            return EnterpriseStore().save_baseline(baseline).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/baselines")
    def baselines() -> dict[str, Any]:
        items = EnterpriseStore().list_baselines()
        return {"baselines": [baseline.model_dump(mode="json") for baseline in items]}

    @app.post("/baselines/{baseline_id}/versions")
    def create_baseline_version(
        baseline_id: str,
        request: BaselineVersionRequest,
    ) -> dict[str, Any]:
        try:
            version = EnterpriseStore().add_baseline_version(
                baseline_id=baseline_id,
                version=request.version,
                policy_ids=request.policy_ids,
                actor=request.actor,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return version.model_dump(mode="json")

    @app.get("/baselines/{baseline_id}/versions")
    def baseline_versions(baseline_id: str) -> dict[str, Any]:
        try:
            versions = EnterpriseStore().list_baseline_versions(baseline_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"versions": [version.model_dump(mode="json") for version in versions]}

    @app.post("/baselines/{baseline_id}/approve")
    def approve_baseline(baseline_id: str, request: PolicyApprovalRequest) -> dict[str, Any]:
        try:
            approval = EnterpriseStore().approve_baseline(
                baseline_id=baseline_id,
                actor=request.actor,
                comment=request.comment,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return approval.model_dump(mode="json")

    @app.get("/baselines/{baseline_id}/approvals")
    def baseline_approvals(baseline_id: str) -> dict[str, Any]:
        try:
            approvals = EnterpriseStore().list_baseline_approvals(baseline_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"approvals": [approval.model_dump(mode="json") for approval in approvals]}

    @app.post("/bindings")
    def create_binding(binding: GroupPolicyBinding) -> dict[str, Any]:
        try:
            return EnterpriseStore().save_binding(binding).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/bindings")
    def bindings(
        target_type: str | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        items = EnterpriseStore().list_bindings()
        if target_type:
            items = [binding for binding in items if binding.target_type == target_type]
        if target:
            items = [binding for binding in items if binding.target == target]
        return {"bindings": [binding.model_dump(mode="json") for binding in items]}

    @app.post("/bindings/resolve")
    def resolve_bindings(request: BindingResolveRequest) -> dict[str, Any]:
        result = resolve_policy_set(
            EnterpriseStore(),
            EvaluationContext(
                org=request.org,
                group=request.group,
                repo=request.repo,
                baseline=request.baseline,
            ),
        )
        return result.model_dump(mode="json")

    @app.post("/integrations/gitlab/groups")
    def create_gitlab_group_binding(binding: GroupPolicyBinding) -> dict[str, Any]:
        if binding.target_type != "group":
            raise HTTPException(
                status_code=400,
                detail="GitLab group bindings require target_type=group.",
            )
        try:
            return EnterpriseStore().save_binding(binding).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/integrations/gitlab/groups/{group_id}/policies")
    def gitlab_group_policies(group_id: str) -> dict[str, Any]:
        store = EnterpriseStore()
        result = resolve_policy_set(store, EvaluationContext(group=group_id))
        return {
            "group_id": group_id,
            "binding_targets": result.binding_targets,
            "baseline_ids": result.baseline_ids,
            "policy_ids": result.policy_ids,
            "policies": result.policies,
        }

    @app.post("/evaluate")
    def evaluate(request: EvaluateRequest) -> dict[str, Any]:
        try:
            result = evaluate_enterprise(
                path=request.path,
                state_path=request.state_path,
                provider=request.provider,
                policy_set=request.policy_set,
                baseline=request.baseline,
                context=request.context,
                fail_on=request.fail_on,
                actor=request.actor,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/service/evaluate")
    def service_evaluate(request: ServiceEvaluateRequest) -> dict[str, Any]:
        if request.evidence_format and request.evidence_format not in {"json", "csv", "pdf"}:
            raise HTTPException(
                status_code=400,
                detail="Evidence format must be json, csv, or pdf.",
            )
        store = EnterpriseStore()
        pack_install = None
        baseline = request.baseline
        try:
            if request.policy_pack:
                pack_install = ensure_policy_pack_installed(
                    request.policy_pack,
                    store=store,
                    actor=request.actor,
                )
                if baseline is None and pack_install.baseline_id:
                    baseline = pack_install.baseline_id
            result = evaluate_enterprise(
                path=request.path,
                state_path=request.state_path,
                provider=request.provider,
                baseline=baseline,
                context=request.context,
                fail_on=request.fail_on,
                store=store,
                actor=request.actor,
                request_id=request.request_id,
                service_metadata={
                    "policy_pack": request.policy_pack,
                    "callback_url": request.callback_url,
                    "service_endpoint": "/service/evaluate",
                },
            )
            export = None
            if request.evidence_format:
                export = export_evidence(
                    result.id,
                    format=request.evidence_format,  # type: ignore[arg-type]
                    store=store,
                    actor=request.actor,
                )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        summary = result.report.get("summary", {})
        payload: dict[str, Any] = {
            "request_id": request.request_id,
            "result_id": result.id,
            "decision": result.decision,
            "status": "completed",
            "summary": summary,
            "links": {
                "result": f"/results/{result.id}",
                "evidence": f"/exports/{export.id}" if export else None,
            },
            "resolved": {
                "baseline": baseline,
                "policy_pack": request.policy_pack,
                "policy_pack_install_id": pack_install.id if pack_install else None,
                "policy_ids": result.resolved_policy_ids,
            },
            "evidence": export.model_dump(mode="json") if export else None,
            "result": result.model_dump(mode="json"),
        }
        return payload

    @app.get("/results/{result_id}")
    def evaluation_result(result_id: str) -> dict[str, Any]:
        try:
            return EnterpriseStore().get_evaluation(result_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/drift/check")
    def drift_check(request: DriftCheckRequest) -> dict[str, Any]:
        try:
            result = check_drift(
                path=request.path,
                state_path=request.state_path,
                snapshot_id=request.snapshot_id,
                update_snapshot=request.update_snapshot,
                actor=request.actor,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/drift/gate")
    def drift_gate(request: DriftGateRequest) -> dict[str, Any]:
        if request.evidence_format and request.evidence_format not in {"json", "csv", "pdf"}:
            raise HTTPException(
                status_code=400,
                detail="Evidence format must be json, csv, or pdf.",
            )
        try:
            result = run_drift_gate(
                path=request.path,
                state_path=request.state_path,
                snapshot_id=request.snapshot_id,
                provider=request.provider,
                policy_set=request.policy_set,
                baseline=request.baseline,
                context=request.context,
                fail_on=request.fail_on,
                update_snapshot=request.update_snapshot,
                create_snapshot=request.create_snapshot,
                export_format=request.evidence_format,  # type: ignore[arg-type]
                actor=request.actor,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/exports")
    def create_export(request: EvidenceExportRequest) -> dict[str, Any]:
        if request.format not in {"json", "csv", "pdf"}:
            raise HTTPException(
                status_code=400,
                detail="Export format must be json, csv, or pdf.",
            )
        try:
            export = export_evidence(
                result_id=request.result_id,
                format=request.format,  # type: ignore[arg-type]
                actor=request.actor,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return export.model_dump(mode="json")

    @app.get("/exports/{export_id}")
    def evidence_export(export_id: str) -> dict[str, Any]:
        try:
            return EnterpriseStore().get_export(export_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app
