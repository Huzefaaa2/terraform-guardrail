from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from terraform_guardrail.enterprise import (
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    EvaluationContext,
    GroupPolicyBinding,
    PolicyMetadata,
    PolicyWaiver,
    evaluate_enterprise,
    preview_policy,
    resolve_policy_set,
)
from terraform_guardrail.scanner.rules import RULE_METADATA, RULES

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
FAVICON_PATH = STATIC_DIR / "favicon.png"
WIKI_BASE_URL = "https://github.com/Huzefaaa2/terraform-guardrail/wiki"
HOW_TO_GUIDES = [
    {
        "title": "Scan a workspace",
        "description": "Upload a Terraform folder or multiple files and read findings.",
        "url": f"{WIKI_BASE_URL}/How-To-Scan-a-Terraform-Workspace",
    },
    {
        "title": "Create a policy",
        "description": "Add owner, compliance, and remediation metadata.",
        "url": f"{WIKI_BASE_URL}/How-To-Create-an-Enterprise-Policy",
    },
    {
        "title": "Use default rules",
        "description": "Understand TG001-TG020 and when to add enterprise policies.",
        "url": f"{WIKI_BASE_URL}/How-To-Use-the-Default-Rule-Catalog",
    },
    {
        "title": "Generate CI evidence",
        "description": "Export JSON or CSV artifacts for audit workflows.",
        "url": f"{WIKI_BASE_URL}/How-To-Generate-CI-Evidence",
    },
]


def create_app() -> FastAPI:
    app = FastAPI(title="Terraform Guardrail MCP (TerraGuard)", version="4.0.0")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request,
        policy_id: str | None = None,
        rule_id: str | None = None,
    ) -> HTMLResponse:
        store = EnterpriseStore()
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(
                request,
                store,
                selected_policy_id=policy_id,
                selected_rule_id=rule_id,
            ),
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> FileResponse:
        return FileResponse(FAVICON_PATH, media_type="image/png")

    @app.post("/scan", response_class=HTMLResponse)
    async def scan(
        request: Request,
        tf_files: Annotated[list[UploadFile], File(...)],
        provider: str = Form("aws"),
        baseline: str = Form(""),
        environment: str = Form("prod"),
        risk_tier: str = Form("high"),
        fail_on: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        uploads = [upload for upload in tf_files if upload.filename]
        if not uploads:
            return templates.TemplateResponse(
                request,
                "index.html",
                _template_context(request, store, error="No files uploaded."),
            )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            for upload in uploads:
                upload_path = _safe_upload_path(tmp_path, upload.filename or "terraform.tf")
                upload_path.parent.mkdir(parents=True, exist_ok=True)
                upload_path.write_bytes(await upload.read())
            try:
                result = evaluate_enterprise(
                    path=tmp_path,
                    provider=provider or None,
                    baseline=baseline or None,
                    context={
                        "environment": environment,
                        "risk_tier": risk_tier,
                    },
                    fail_on=fail_on or None,
                    store=store,
                    actor="web",
                )
            except Exception as exc:  # noqa: BLE001
                return templates.TemplateResponse(
                    request,
                    "index.html",
                    _template_context(request, store, error=str(exc)),
                )
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, evaluation=result, report=result.report),
        )

    @app.post("/policies", response_class=HTMLResponse)
    async def create_policy(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        owner: str = Form(""),
        standard: str = Form(""),
        control_id: str = Form(""),
        remediation: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            rule_id = _next_rule_id(store)
            store.save_policy(
                EnterprisePolicy(
                    name=name,
                    description=description,
                    rule_id=rule_id,
                    metadata=PolicyMetadata(
                        owner=owner or None,
                        standard=standard or None,
                        control_id=control_id or None,
                        remediation=remediation or None,
                    ),
                )
            )
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/policies/{policy_id}/approve", response_class=HTMLResponse)
    async def approve_policy(request: Request, policy_id: str) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.approve_policy(policy_id, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error, selected_policy_id=policy_id),
        )

    @app.post("/policies/{policy_id}/preview", response_class=HTMLResponse)
    async def preview_enterprise_policy(
        request: Request,
        policy_id: str,
        preview_files: Annotated[list[UploadFile], File(...)] = None,
    ) -> HTMLResponse:
        store = EnterpriseStore()
        uploads = [upload for upload in preview_files or [] if upload.filename]
        if not uploads:
            return templates.TemplateResponse(
                request,
                "index.html",
                _template_context(
                    request,
                    store,
                    error="No preview files uploaded.",
                    selected_policy_id=policy_id,
                ),
            )
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            for upload in uploads:
                upload_path = _safe_upload_path(tmp_path, upload.filename or "terraform.tf")
                upload_path.parent.mkdir(parents=True, exist_ok=True)
                upload_path.write_bytes(await upload.read())
            try:
                preview = preview_policy(
                    policy_id=policy_id,
                    path=tmp_path,
                    store=store,
                    actor="web",
                )
                error = None
            except Exception as exc:  # noqa: BLE001
                preview = None
                error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(
                request,
                store,
                error=error,
                selected_policy_id=policy_id,
                preview=preview,
            ),
        )

    @app.post("/policies/{policy_id}", response_class=HTMLResponse)
    async def update_policy(
        request: Request,
        policy_id: str,
        name: str = Form(...),
        description: str = Form(""),
        rule_id: str = Form(""),
        owner: str = Form(""),
        standard: str = Form(""),
        control_id: str = Form(""),
        remediation: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            policy = store.get_policy(policy_id)
            policy.name = name
            policy.description = description
            policy.rule_id = rule_id or None
            policy.metadata.owner = owner or None
            policy.metadata.standard = standard or None
            policy.metadata.control_id = control_id or None
            policy.metadata.remediation = remediation or None
            store.save_policy(policy, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error, selected_policy_id=policy_id),
        )

    @app.post("/bindings", response_class=HTMLResponse)
    async def create_binding(
        request: Request,
        target_type: str = Form(...),
        target: str = Form(...),
        policy_id: str = Form(""),
        baseline_id: str = Form(""),
        parent: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            binding = GroupPolicyBinding(
                target_type=target_type,  # type: ignore[arg-type]
                target=target,
                policy_ids=[policy_id] if policy_id else [],
                baseline_ids=[baseline_id] if baseline_id else [],
                parent=parent or None,
            )
            store.save_binding(binding, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/bindings/resolve", response_class=HTMLResponse)
    async def resolve_bindings(
        request: Request,
        org: str = Form(""),
        group: str = Form(""),
        repo: str = Form(""),
        baseline: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            resolved = resolve_policy_set(
                store,
                EvaluationContext(
                    org=org or None,
                    group=group or None,
                    repo=repo or None,
                    baseline=baseline or None,
                ),
            )
            error = None
        except Exception as exc:  # noqa: BLE001
            resolved = None
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error, resolved=resolved),
        )

    @app.post("/waivers", response_class=HTMLResponse)
    async def create_waiver(
        request: Request,
        rule_id: str = Form(...),
        reason: str = Form(...),
        owner: str = Form(...),
        expires_at: str = Form(...),
        path: str = Form(""),
        approve: bool = Form(False),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            waiver = store.save_waiver(
                PolicyWaiver(
                    rule_id=rule_id,
                    reason=reason,
                    owner=owner,
                    expires_at=expires_at,
                    path=path or None,
                    requested_by="web",
                ),
                actor="web",
            )
            if approve:
                store.approve_waiver(waiver.id, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/waivers/{waiver_id}/approve", response_class=HTMLResponse)
    async def approve_waiver(request: Request, waiver_id: str) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.approve_waiver(waiver_id, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/waivers/{waiver_id}/revoke", response_class=HTMLResponse)
    async def revoke_waiver(request: Request, waiver_id: str) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.revoke_waiver(waiver_id, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/baselines", response_class=HTMLResponse)
    async def create_baseline(
        request: Request,
        name: str = Form(...),
        policy_id: str = Form(""),
        scope: str = Form("org"),
        version: str = Form("0.1.0"),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.save_baseline(
                Baseline(
                    name=name,
                    policy_ids=[policy_id] if policy_id else [],
                    scope=scope,  # type: ignore[arg-type]
                    version=version,
                ),
                actor="web",
            )
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/baselines/{baseline_id}/version", response_class=HTMLResponse)
    async def create_baseline_version(
        request: Request,
        baseline_id: str,
        version: str = Form(...),
        policy_id: str = Form(""),
    ) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.add_baseline_version(
                baseline_id=baseline_id,
                version=version,
                policy_ids=[policy_id] if policy_id else None,
                actor="web",
            )
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    @app.post("/baselines/{baseline_id}/approve", response_class=HTMLResponse)
    async def approve_baseline(request: Request, baseline_id: str) -> HTMLResponse:
        store = EnterpriseStore()
        try:
            store.approve_baseline(baseline_id, actor="web")
            error = None
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            _template_context(request, store, error=error),
        )

    return app


def _template_context(
    request: Request,
    store: EnterpriseStore,
    report=None,  # type: ignore[no-untyped-def]
    evaluation=None,  # type: ignore[no-untyped-def]
    error: str | None = None,
    selected_policy_id: str | None = None,
    selected_rule_id: str | None = None,
    preview=None,  # type: ignore[no-untyped-def]
    resolved=None,  # type: ignore[no-untyped-def]
) -> dict:
    policies = sorted(
        store.list_policies(),
        key=lambda policy: (_rule_number(policy.rule_id), policy.name.lower()),
    )
    default_rules = _default_rule_views()
    selected_policy = None
    selected_default_rule = None
    if selected_rule_id:
        selected_default_rule = _default_rule_view(selected_rule_id)
    if selected_policy_id:
        for policy in policies:
            if policy.id == selected_policy_id:
                selected_policy = policy
                break
    if selected_policy is None and selected_default_rule is None and policies:
        selected_policy = policies[0]
    if selected_policy is None and selected_default_rule is None and default_rules:
        selected_default_rule = default_rules[0]
    return {
        "request": request,
        "report": report,
        "evaluation": evaluation,
        "error": error,
        "policies": policies,
        "baselines": store.list_baselines(),
        "bindings": store.list_bindings(),
        "waivers": store.list_waivers(),
        "risk_profiles": store.list_risk_profiles(),
        "default_rules": default_rules,
        "selected_policy": selected_policy,
        "selected_default_rule": selected_default_rule,
        "preview": preview,
        "resolved": resolved,
        "next_rule_id": _next_rule_id(store),
        "how_to_guides": HOW_TO_GUIDES,
        "how_to_guides_url": f"{WIKI_BASE_URL}/How-To-Guides",
    }


def _safe_upload_path(root: Path, filename: str) -> Path:
    parts = [
        part
        for part in Path(filename.replace("\\", "/")).parts
        if part not in {"", ".", ".."}
    ]
    if not parts:
        parts = ["terraform.tf"]
    return root.joinpath(*parts)


def _next_rule_id(store: EnterpriseStore) -> str:
    used = set(RULES)
    for policy in store.list_policies():
        if policy.rule_id:
            used.add(policy.rule_id)
    highest = max((_rule_number(rule_id) for rule_id in used), default=0)
    return f"TG{highest + 1:03d}"


def _default_rule_views() -> list[dict[str, str]]:
    return [
        {
            "rule_id": rule_id,
            "name": name,
            "risk": RULE_METADATA.get(rule_id, {}).get("risk", "unknown"),
            "remediation": RULE_METADATA.get(rule_id, {}).get("remediation", "Review the finding."),
        }
        for rule_id, name in sorted(RULES.items(), key=lambda item: _rule_number(item[0]))
    ]


def _default_rule_view(rule_id: str) -> dict[str, str] | None:
    name = RULES.get(rule_id)
    if not name:
        return None
    metadata = RULE_METADATA.get(rule_id, {})
    return {
        "rule_id": rule_id,
        "name": name,
        "risk": metadata.get("risk", "unknown"),
        "remediation": metadata.get("remediation", "Review the finding."),
    }


def _rule_number(rule_id: str | None) -> int:
    if not rule_id or not rule_id.startswith("TG"):
        return 999999
    try:
        return int(rule_id[2:])
    except ValueError:
        return 999999
