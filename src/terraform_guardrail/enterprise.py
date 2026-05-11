from __future__ import annotations

import csv
import json
import os
import uuid
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from terraform_guardrail.scanner.models import ScanReport
from terraform_guardrail.scanner.rules import RULE_METADATA
from terraform_guardrail.scanner.scan import scan_path

DEFAULT_ENTERPRISE_DATA_DIR = Path(".guardrail/enterprise")
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class PolicyMetadata(BaseModel):
    standard: str | None = None
    control_id: str | None = None
    owner: str | None = None
    expiry: str | None = None
    risk: str | None = None
    remediation: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class EnterprisePolicy(BaseModel):
    id: str = Field(default_factory=lambda: new_id("pol"))
    name: str
    description: str = ""
    category: Literal["security", "cost", "resiliency", "compliance"] = "security"
    severity: Literal["info", "warn", "block"] = "warn"
    scope: Literal["org", "group", "repo"] = "org"
    providers: list[str] = Field(default_factory=list)
    rule_type: Literal["rego", "native", "invariant"] = "native"
    rule_body: str = ""
    rule_id: str | None = None
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    status: Literal["draft", "review", "approved", "active", "deprecated"] = "draft"
    version: str = "0.1.0"
    baseline_policy: bool = False
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class PolicyVersion(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ver"))
    policy_id: str
    version: str
    rule_body: str = ""
    status: Literal["draft", "review", "approved", "active", "deprecated"] = "draft"
    created_at: str = Field(default_factory=utc_now)
    created_by: str = "system"


class PolicyApproval(BaseModel):
    id: str = Field(default_factory=lambda: new_id("appr"))
    policy_id: str
    version: str
    actor: str = "system"
    status: Literal["approved", "rejected"] = "approved"
    comment: str | None = None
    created_at: str = Field(default_factory=utc_now)


class Baseline(BaseModel):
    id: str = Field(default_factory=lambda: new_id("base"))
    name: str
    policy_ids: list[str] = Field(default_factory=list)
    scope: Literal["org", "group", "repo"] = "org"
    version: str = "0.1.0"
    approved: bool = False
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class BaselineVersion(BaseModel):
    id: str = Field(default_factory=lambda: new_id("bver"))
    baseline_id: str
    version: str
    policy_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
    created_by: str = "system"


class BaselineApproval(BaseModel):
    id: str = Field(default_factory=lambda: new_id("bappr"))
    baseline_id: str
    version: str
    actor: str = "system"
    status: Literal["approved", "rejected"] = "approved"
    comment: str | None = None
    created_at: str = Field(default_factory=utc_now)


class GroupPolicyBinding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("bind"))
    target_type: Literal["org", "group", "repo"]
    target: str
    policy_ids: list[str] = Field(default_factory=list)
    baseline_ids: list[str] = Field(default_factory=list)
    parent: str | None = None
    created_at: str = Field(default_factory=utc_now)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("audit"))
    actor: str = "system"
    action: str
    resource: str
    timestamp: str = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationContext(BaseModel):
    provider: str | None = None
    policy_set: str | None = None
    baseline: str | None = None
    environment: str | None = None
    app: str | None = None
    org: str | None = None
    group: str | None = None
    repo: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("eval"))
    request_id: str | None = None
    created_at: str = Field(default_factory=utc_now)
    decision: Literal["pass", "warn", "block"]
    context: EvaluationContext = Field(default_factory=EvaluationContext)
    resolved_policy_ids: list[str] = Field(default_factory=list)
    report: dict[str, Any]
    evidence_id: str | None = None
    service_metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceExport(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evid"))
    result_id: str
    format: Literal["json", "csv", "pdf"] = "json"
    path: str
    created_at: str = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DriftSnapshot(BaseModel):
    id: str
    created_at: str = Field(default_factory=utc_now)
    signature: list[str] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)


class DriftCheck(BaseModel):
    id: str = Field(default_factory=lambda: new_id("drift"))
    snapshot_id: str
    created_at: str = Field(default_factory=utc_now)
    drifted: bool
    status: Literal["baseline_created", "matched", "changed"]
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


class DriftGateResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("gate"))
    created_at: str = Field(default_factory=utc_now)
    decision: Literal["pass", "warn", "block"]
    evaluation: EvaluationResult
    drift: DriftCheck
    evidence: EvidenceExport | None = None
    reasons: list[str] = Field(default_factory=list)


class PolicyPreviewResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("preview"))
    created_at: str = Field(default_factory=utc_now)
    policy_id: str
    policy_name: str
    rule_id: str | None = None
    scanned_path: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class ResolvedPolicySet(BaseModel):
    id: str = Field(default_factory=lambda: new_id("resolved"))
    created_at: str = Field(default_factory=utc_now)
    target_type: Literal["org", "group", "repo"]
    target: str
    context: EvaluationContext
    binding_targets: list[str] = Field(default_factory=list)
    baseline_ids: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)


class PolicyPackTemplate(BaseModel):
    name: str
    description: str = ""
    rule_id: str
    severity: Literal["info", "warn", "block"] = "warn"
    category: Literal["security", "cost", "resiliency", "compliance"] = "security"
    scope: Literal["org", "group", "repo"] = "org"
    providers: list[str] = Field(default_factory=list)
    rule_type: Literal["rego", "native", "invariant"] = "native"
    rule_body: str = ""
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    baseline_policy: bool = True


class PolicyPack(BaseModel):
    id: str
    name: str
    version: str = "0.1.0"
    category: Literal["security", "cost", "resiliency", "compliance"] = "security"
    providers: list[str] = Field(default_factory=list)
    standards: list[str] = Field(default_factory=list)
    description: str = ""
    baseline_name: str | None = None
    policies: list[PolicyPackTemplate] = Field(default_factory=list)


class PolicyPackInstallResult(BaseModel):
    id: str = Field(default_factory=lambda: new_id("pack_install"))
    pack_id: str
    pack_name: str
    version: str
    installed_at: str = Field(default_factory=utc_now)
    policy_ids: list[str] = Field(default_factory=list)
    baseline_id: str | None = None


class EnterpriseStore:
    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root else enterprise_data_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "evidence").mkdir(parents=True, exist_ok=True)

    def list_policies(self) -> list[EnterprisePolicy]:
        return [EnterprisePolicy.model_validate(item) for item in self._read_list("policies")]

    def get_policy(self, policy_id: str) -> EnterprisePolicy:
        for policy in self.list_policies():
            if policy.id == policy_id:
                return policy
        raise KeyError(f"Policy not found: {policy_id}")

    def save_policy(self, policy: EnterprisePolicy, actor: str = "system") -> EnterprisePolicy:
        policies = self.list_policies()
        for idx, current in enumerate(policies):
            if current.id == policy.id:
                policy.updated_at = utc_now()
                policies[idx] = policy
                self._write_models("policies", policies)
                self.add_audit(actor, "policy.update", policy.id, {"version": policy.version})
                return policy
        policies.append(policy)
        self._write_models("policies", policies)
        self.add_audit(actor, "policy.create", policy.id, {"version": policy.version})
        return policy

    def add_policy_version(
        self,
        policy_id: str,
        version: str,
        rule_body: str = "",
        actor: str = "system",
    ) -> PolicyVersion:
        policy = self.get_policy(policy_id)
        policy.version = version
        if rule_body:
            policy.rule_body = rule_body
        policy.updated_at = utc_now()
        self.save_policy(policy, actor=actor)
        versions = self.list_policy_versions(policy_id)
        created = PolicyVersion(
            policy_id=policy_id,
            version=version,
            rule_body=rule_body or policy.rule_body,
            created_by=actor,
        )
        versions.append(created)
        all_versions = [
            PolicyVersion.model_validate(item) for item in self._read_list("policy_versions")
        ]
        all_versions.append(created)
        self._write_models("policy_versions", all_versions)
        self.add_audit(actor, "policy.version.create", policy_id, {"version": version})
        return created

    def list_policy_versions(self, policy_id: str) -> list[PolicyVersion]:
        return [
            PolicyVersion.model_validate(item)
            for item in self._read_list("policy_versions")
            if item.get("policy_id") == policy_id
        ]

    def approve_policy(
        self,
        policy_id: str,
        actor: str = "system",
        comment: str | None = None,
    ) -> PolicyApproval:
        policy = self.get_policy(policy_id)
        policy.status = "approved"
        policy.updated_at = utc_now()
        self.save_policy(policy, actor=actor)
        approval = PolicyApproval(
            policy_id=policy.id,
            version=policy.version,
            actor=actor,
            comment=comment,
        )
        approvals = [
            PolicyApproval.model_validate(item) for item in self._read_list("policy_approvals")
        ]
        approvals.append(approval)
        self._write_models("policy_approvals", approvals)
        self.add_audit(actor, "policy.approve", policy.id, {"version": policy.version})
        return approval

    def list_baselines(self) -> list[Baseline]:
        return [Baseline.model_validate(item) for item in self._read_list("baselines")]

    def save_baseline(self, baseline: Baseline, actor: str = "system") -> Baseline:
        baselines = self.list_baselines()
        for idx, current in enumerate(baselines):
            if current.id == baseline.id:
                baseline.updated_at = utc_now()
                baselines[idx] = baseline
                self._write_models("baselines", baselines)
                self.add_audit(actor, "baseline.update", baseline.id, {})
                return baseline
        baselines.append(baseline)
        self._write_models("baselines", baselines)
        self.add_audit(actor, "baseline.create", baseline.id, {"policy_ids": baseline.policy_ids})
        return baseline

    def get_baseline(self, baseline_id_or_name: str) -> Baseline:
        for baseline in self.list_baselines():
            if baseline.id == baseline_id_or_name or baseline.name == baseline_id_or_name:
                return baseline
        raise KeyError(f"Baseline not found: {baseline_id_or_name}")

    def add_baseline_version(
        self,
        baseline_id: str,
        version: str,
        policy_ids: list[str] | None = None,
        actor: str = "system",
    ) -> BaselineVersion:
        baseline = self.get_baseline(baseline_id)
        baseline.version = version
        if policy_ids is not None:
            baseline.policy_ids = policy_ids
        baseline.approved = False
        baseline.updated_at = utc_now()
        self.save_baseline(baseline, actor=actor)
        created = BaselineVersion(
            baseline_id=baseline.id,
            version=baseline.version,
            policy_ids=baseline.policy_ids,
            created_by=actor,
        )
        versions = [
            BaselineVersion.model_validate(item)
            for item in self._read_list("baseline_versions")
        ]
        versions.append(created)
        self._write_models("baseline_versions", versions)
        self.add_audit(
            actor,
            "baseline.version.create",
            baseline.id,
            {"version": baseline.version, "policy_ids": baseline.policy_ids},
        )
        return created

    def list_baseline_versions(self, baseline_id: str) -> list[BaselineVersion]:
        baseline = self.get_baseline(baseline_id)
        return [
            BaselineVersion.model_validate(item)
            for item in self._read_list("baseline_versions")
            if item.get("baseline_id") == baseline.id
        ]

    def approve_baseline(
        self,
        baseline_id: str,
        actor: str = "system",
        comment: str | None = None,
    ) -> BaselineApproval:
        baseline = self.get_baseline(baseline_id)
        baseline.approved = True
        baseline.updated_at = utc_now()
        self.save_baseline(baseline, actor=actor)
        approval = BaselineApproval(
            baseline_id=baseline.id,
            version=baseline.version,
            actor=actor,
            comment=comment,
        )
        approvals = [
            BaselineApproval.model_validate(item)
            for item in self._read_list("baseline_approvals")
        ]
        approvals.append(approval)
        self._write_models("baseline_approvals", approvals)
        self.add_audit(actor, "baseline.approve", baseline.id, {"version": baseline.version})
        return approval

    def list_baseline_approvals(self, baseline_id: str) -> list[BaselineApproval]:
        baseline = self.get_baseline(baseline_id)
        return [
            BaselineApproval.model_validate(item)
            for item in self._read_list("baseline_approvals")
            if item.get("baseline_id") == baseline.id
        ]

    def list_bindings(self) -> list[GroupPolicyBinding]:
        return [GroupPolicyBinding.model_validate(item) for item in self._read_list("bindings")]

    def list_installed_pack_results(self) -> list[PolicyPackInstallResult]:
        return [
            PolicyPackInstallResult.model_validate(item)
            for item in self._read_list("policy_pack_installs")
        ]

    def install_policy_pack(
        self,
        pack: PolicyPack,
        actor: str = "system",
        approve: bool = True,
        create_baseline: bool = True,
    ) -> PolicyPackInstallResult:
        created_policy_ids: list[str] = []
        for template in pack.policies:
            policy = EnterprisePolicy(
                name=template.name,
                description=template.description,
                category=template.category,
                severity=template.severity,
                scope=template.scope,
                providers=template.providers,
                rule_type=template.rule_type,
                rule_body=template.rule_body,
                rule_id=template.rule_id,
                metadata=template.metadata,
                version=pack.version,
                baseline_policy=template.baseline_policy,
            )
            saved = self.save_policy(policy, actor=actor)
            if approve:
                self.approve_policy(saved.id, actor=actor, comment=f"Installed from {pack.id}")
            created_policy_ids.append(saved.id)

        baseline_id = None
        if create_baseline:
            baseline = self.save_baseline(
                Baseline(
                    name=pack.baseline_name or f"{pack.id}-baseline",
                    policy_ids=created_policy_ids,
                    version=pack.version,
                    approved=approve,
                ),
                actor=actor,
            )
            baseline_id = baseline.id

        result = PolicyPackInstallResult(
            pack_id=pack.id,
            pack_name=pack.name,
            version=pack.version,
            policy_ids=created_policy_ids,
            baseline_id=baseline_id,
        )
        installs = self.list_installed_pack_results()
        installs.append(result)
        self._write_models("policy_pack_installs", installs)
        self.add_audit(
            actor,
            "policy_pack.install",
            pack.id,
            {
                "version": pack.version,
                "policy_ids": created_policy_ids,
                "baseline_id": baseline_id,
            },
        )
        return result

    def save_binding(
        self,
        binding: GroupPolicyBinding,
        actor: str = "system",
    ) -> GroupPolicyBinding:
        bindings = self.list_bindings()
        bindings.append(binding)
        self._write_models("bindings", bindings)
        self.add_audit(actor, "binding.create", binding.id, binding.model_dump())
        return binding

    def save_evaluation(self, result: EvaluationResult, actor: str = "system") -> EvaluationResult:
        results = [
            EvaluationResult.model_validate(item) for item in self._read_list("evaluations")
        ]
        results.append(result)
        self._write_models("evaluations", results)
        self.add_audit(
            actor,
            "evaluation.create",
            result.id,
            {"decision": result.decision, "policy_ids": result.resolved_policy_ids},
        )
        return result

    def get_evaluation(self, result_id: str) -> EvaluationResult:
        for result in self._read_list("evaluations"):
            if result.get("id") == result_id:
                return EvaluationResult.model_validate(result)
        raise KeyError(f"Evaluation not found: {result_id}")

    def save_export(self, export: EvidenceExport, actor: str = "system") -> EvidenceExport:
        exports = [EvidenceExport.model_validate(item) for item in self._read_list("exports")]
        exports.append(export)
        self._write_models("exports", exports)
        self.add_audit(
            actor,
            "evidence.export",
            export.id,
            {"result_id": export.result_id, "format": export.format},
        )
        return export

    def get_export(self, export_id: str) -> EvidenceExport:
        for export in self._read_list("exports"):
            if export.get("id") == export_id:
                return EvidenceExport.model_validate(export)
        raise KeyError(f"Evidence export not found: {export_id}")

    def get_snapshot(self, snapshot_id: str) -> DriftSnapshot | None:
        for snapshot in self._read_list("drift_snapshots"):
            if snapshot.get("id") == snapshot_id:
                return DriftSnapshot.model_validate(snapshot)
        return None

    def save_snapshot(self, snapshot: DriftSnapshot) -> DriftSnapshot:
        snapshots = [
            DriftSnapshot.model_validate(item) for item in self._read_list("drift_snapshots")
        ]
        for idx, current in enumerate(snapshots):
            if current.id == snapshot.id:
                snapshots[idx] = snapshot
                self._write_models("drift_snapshots", snapshots)
                return snapshot
        snapshots.append(snapshot)
        self._write_models("drift_snapshots", snapshots)
        return snapshot

    def save_drift_check(self, check: DriftCheck, actor: str = "system") -> DriftCheck:
        checks = [DriftCheck.model_validate(item) for item in self._read_list("drift_checks")]
        checks.append(check)
        self._write_models("drift_checks", checks)
        self.add_audit(actor, "drift.check", check.id, check.model_dump())
        return check

    def save_drift_gate(self, result: DriftGateResult, actor: str = "system") -> DriftGateResult:
        gates = [DriftGateResult.model_validate(item) for item in self._read_list("drift_gates")]
        gates.append(result)
        self._write_models("drift_gates", gates)
        self.add_audit(
            actor,
            "drift.gate",
            result.id,
            {
                "decision": result.decision,
                "evaluation_id": result.evaluation.id,
                "drift_id": result.drift.id,
                "evidence_id": result.evidence.id if result.evidence else None,
            },
        )
        return result

    def save_policy_preview(
        self,
        result: PolicyPreviewResult,
        actor: str = "system",
    ) -> PolicyPreviewResult:
        previews = [
            PolicyPreviewResult.model_validate(item)
            for item in self._read_list("policy_previews")
        ]
        previews.append(result)
        self._write_models("policy_previews", previews)
        self.add_audit(
            actor,
            "policy.preview",
            result.id,
            {
                "policy_id": result.policy_id,
                "rule_id": result.rule_id,
                "findings": result.summary.get("findings", 0),
            },
        )
        return result

    def audit_events(self) -> list[AuditEvent]:
        return [AuditEvent.model_validate(item) for item in self._read_list("audit_events")]

    def add_audit(
        self,
        actor: str,
        action: str,
        resource: str,
        metadata: dict[str, Any],
    ) -> AuditEvent:
        events = self.audit_events()
        event = AuditEvent(actor=actor, action=action, resource=resource, metadata=metadata)
        events.append(event)
        self._write_models("audit_events", events)
        return event

    def _read_list(self, name: str) -> list[dict[str, Any]]:
        path = self.root / f"{name}.json"
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"Enterprise store file must contain a list: {path}")
        return data

    def _write_models(self, name: str, items: list[BaseModel]) -> None:
        path = self.root / f"{name}.json"
        payload = [item.model_dump(mode="json") for item in items]
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def enterprise_data_dir() -> Path:
    return Path(os.getenv("GUARDRAIL_ENTERPRISE_DATA_DIR", DEFAULT_ENTERPRISE_DATA_DIR))


def list_builtin_policy_packs() -> list[PolicyPack]:
    data = resources.files("terraform_guardrail.policy_packs").joinpath("packs.json")
    payload = json.loads(data.read_text(encoding="utf-8"))
    return [PolicyPack.model_validate(item) for item in payload]


def get_builtin_policy_pack(pack_id: str) -> PolicyPack:
    for pack in list_builtin_policy_packs():
        if pack.id == pack_id:
            return pack
    raise KeyError(f"Policy pack not found: {pack_id}")


def install_policy_pack(
    pack_id: str,
    store: EnterpriseStore | None = None,
    actor: str = "system",
    approve: bool = True,
    create_baseline: bool = True,
) -> PolicyPackInstallResult:
    store = store or EnterpriseStore()
    pack = get_builtin_policy_pack(pack_id)
    return store.install_policy_pack(
        pack,
        actor=actor,
        approve=approve,
        create_baseline=create_baseline,
    )


def ensure_policy_pack_installed(
    pack_id: str,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> PolicyPackInstallResult:
    store = store or EnterpriseStore()
    pack = get_builtin_policy_pack(pack_id)
    for install in reversed(store.list_installed_pack_results()):
        if install.pack_id == pack.id and install.version == pack.version:
            return install
    return store.install_policy_pack(pack, actor=actor, approve=True, create_baseline=True)


def evaluate_enterprise(
    path: Path | str,
    state_path: Path | str | None = None,
    provider: str | None = None,
    policy_set: str | None = None,
    baseline: str | None = None,
    context: dict[str, Any] | None = None,
    fail_on: str | None = None,
    store: EnterpriseStore | None = None,
    actor: str = "system",
    request_id: str | None = None,
    service_metadata: dict[str, Any] | None = None,
) -> EvaluationResult:
    store = store or EnterpriseStore()
    ctx = EvaluationContext(provider=provider, policy_set=policy_set, baseline=baseline)
    if context:
        for key in ("environment", "app", "org", "group", "repo"):
            if key in context:
                setattr(ctx, key, context[key])
        ctx.extra = {key: value for key, value in context.items() if not hasattr(ctx, key)}

    report = scan_path(Path(path), state_path=state_path)
    resolved_policy_ids = resolve_policy_ids(store, ctx)
    enrich_report_findings(report, store, resolved_policy_ids)
    decision = decide(report, resolved_policy_ids, store, fail_on=fail_on)
    result = EvaluationResult(
        request_id=request_id,
        decision=decision,
        context=ctx,
        resolved_policy_ids=resolved_policy_ids,
        report=report.model_dump(mode="json"),
        service_metadata=service_metadata or {},
    )
    return store.save_evaluation(result, actor=actor)


def resolve_policy_ids(store: EnterpriseStore, context: EvaluationContext) -> list[str]:
    return resolve_policy_set(store, context).policy_ids


def resolve_policy_set(store: EnterpriseStore, context: EvaluationContext) -> ResolvedPolicySet:
    resolved_policy_ids: list[str] = []
    baseline_ids: list[str] = []
    if context.baseline:
        try:
            baseline = store.get_baseline(context.baseline)
            baseline_ids.append(baseline.id)
            resolved_policy_ids.extend(baseline.policy_ids)
        except KeyError:
            pass
    for baseline in store.list_baselines():
        if baseline.approved and baseline.scope == "org":
            baseline_ids.append(baseline.id)
            resolved_policy_ids.extend(baseline.policy_ids)
    bindings = store.list_bindings()
    targets = _resolved_binding_targets(bindings, context)
    for binding in bindings:
        if (binding.target_type, binding.target) not in targets:
            continue
        resolved_policy_ids.extend(binding.policy_ids)
        for baseline_id in binding.baseline_ids:
            try:
                baseline = store.get_baseline(baseline_id)
                baseline_ids.append(baseline.id)
                resolved_policy_ids.extend(baseline.policy_ids)
            except KeyError:
                continue
    policy_ids = list(dict.fromkeys(resolved_policy_ids))
    policies = []
    for policy_id in policy_ids:
        try:
            policies.append(store.get_policy(policy_id).model_dump(mode="json"))
        except KeyError:
            continue
    target_type, target = _primary_context_target(context)
    return ResolvedPolicySet(
        target_type=target_type,
        target=target,
        context=context,
        binding_targets=[
            f"{target_type}:{target}"
            for target_type, target in sorted(targets, key=lambda item: (item[0], item[1]))
        ],
        baseline_ids=list(dict.fromkeys(baseline_ids)),
        policy_ids=policy_ids,
        policies=policies,
    )


def enrich_report_findings(
    report: ScanReport,
    store: EnterpriseStore,
    policy_ids: list[str] | None = None,
) -> None:
    policies = store.list_policies()
    if policy_ids:
        allowed = set(policy_ids)
        policies = [policy for policy in policies if policy.id in allowed]
    by_rule: dict[str, EnterprisePolicy] = {}
    for policy in policies:
        key = policy.rule_id or policy.id
        by_rule[key] = policy

    for finding in report.findings:
        policy = by_rule.get(finding.rule_id)
        if policy is None and finding.rule_id in {"TG021", "TG022", "TG023"}:
            detail = finding.detail or {}
            resource = detail.get("resource")
            if isinstance(resource, str):
                policy = _policy_for_invariant_finding(finding.rule_id, resource, by_rule)
        rule_metadata = RULE_METADATA.get(finding.rule_id, {})
        if policy:
            finding.owner = policy.metadata.owner
            finding.standard = policy.metadata.standard
            finding.control_id = policy.metadata.control_id
            finding.risk = policy.metadata.risk or rule_metadata.get("risk")
            finding.expiry = policy.metadata.expiry
            finding.remediation = policy.metadata.remediation or rule_metadata.get("remediation")
        else:
            finding.risk = rule_metadata.get("risk")
            finding.remediation = rule_metadata.get("remediation")
        detail = finding.detail or {}
        if policy:
            detail.setdefault("policy_id", policy.id)
            detail.setdefault("policy_status", policy.status)
        if rule_metadata:
            detail.setdefault("default_risk", rule_metadata.get("risk"))
            detail.setdefault("recommendation", rule_metadata.get("remediation"))
        finding.detail = detail


def _policy_for_invariant_finding(
    rule_id: str,
    resource: str,
    by_rule: dict[str, EnterprisePolicy],
) -> EnterprisePolicy | None:
    rule_map = {
        "TG021": (
            "TG006",
            "TG007",
            "TG008",
            "TG010",
            "TG015",
            "TG019",
        ),
        "TG022": ("TG011", "TG012", "TG020"),
        "TG023": ("TG016",),
    }
    for mapped_rule in rule_map.get(rule_id, ()):
        policy = by_rule.get(mapped_rule)
        if policy and _policy_resource_matches(policy.rule_id, resource):
            return policy
    return None


def _policy_resource_matches(rule_id: str | None, resource: str) -> bool:
    if rule_id == "TG011":
        return resource.startswith("aws_s3_bucket.")
    if rule_id == "TG012":
        return resource.startswith(("aws_db_instance.", "aws_rds_cluster."))
    if rule_id == "TG020":
        return resource.startswith("aws_ebs_volume.")
    if rule_id == "TG019":
        return resource.startswith("azurerm_storage_account.")
    return True


def decide(
    report: ScanReport,
    policy_ids: list[str],
    store: EnterpriseStore,
    fail_on: str | None = None,
) -> Literal["pass", "warn", "block"]:
    threshold = fail_on or "high"
    if threshold not in SEVERITY_ORDER:
        threshold = "high"
    if _findings_at_or_above(report, threshold):
        return "block"
    policies = [
        store.get_policy(policy_id)
        for policy_id in policy_ids
        if _policy_exists(store, policy_id)
    ]
    if any(
        policy.status in {"approved", "active"} and policy.severity == "block"
        for policy in policies
    ):
        if report.summary.findings > 0:
            return "block"
    if report.summary.medium > 0:
        return "warn"
    return "pass"


def export_evidence(
    result_id: str,
    format: Literal["json", "csv", "pdf"] = "json",
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> EvidenceExport:
    store = store or EnterpriseStore()
    result = store.get_evaluation(result_id)
    export_id = new_id("evid")
    path = store.root / "evidence" / f"{export_id}.{format}"
    if format == "json":
        path.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    elif format == "csv":
        _write_evidence_csv(path, result)
    elif format == "pdf":
        _write_evidence_pdf(path, result)
    else:
        raise ValueError("Evidence format must be json, csv, or pdf.")
    export = EvidenceExport(id=export_id, result_id=result.id, format=format, path=str(path))
    result.evidence_id = export.id
    _replace_evaluation(store, result)
    return store.save_export(export, actor=actor)


def check_drift(
    path: Path | str,
    state_path: Path | str | None = None,
    snapshot_id: str = "default",
    update_snapshot: bool = False,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> DriftCheck:
    store = store or EnterpriseStore()
    report = scan_path(Path(path), state_path=state_path)
    signature = finding_signature(report)
    snapshot = store.get_snapshot(snapshot_id)
    if snapshot is None:
        store.save_snapshot(
            DriftSnapshot(
                id=snapshot_id,
                signature=signature,
                report=report.model_dump(mode="json"),
            )
        )
        return store.save_drift_check(
            DriftCheck(snapshot_id=snapshot_id, drifted=False, status="baseline_created"),
            actor=actor,
        )

    current = set(signature)
    previous = set(snapshot.signature)
    added = sorted(current - previous)
    removed = sorted(previous - current)
    drifted = bool(added or removed)
    if update_snapshot:
        store.save_snapshot(
            DriftSnapshot(
                id=snapshot_id,
                signature=signature,
                report=report.model_dump(mode="json"),
            )
        )
    return store.save_drift_check(
        DriftCheck(
            snapshot_id=snapshot_id,
            drifted=drifted,
            status="changed" if drifted else "matched",
            added=added,
            removed=removed,
        ),
        actor=actor,
    )


def run_drift_gate(
    path: Path | str,
    state_path: Path | str | None = None,
    snapshot_id: str = "default",
    provider: str | None = None,
    policy_set: str | None = None,
    baseline: str | None = None,
    context: dict[str, Any] | None = None,
    fail_on: str | None = None,
    update_snapshot: bool = False,
    create_snapshot: bool = True,
    export_format: Literal["json", "csv", "pdf"] | None = None,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> DriftGateResult:
    store = store or EnterpriseStore()
    evaluation = evaluate_enterprise(
        path=path,
        state_path=state_path,
        provider=provider,
        policy_set=policy_set,
        baseline=baseline,
        context=context,
        fail_on=fail_on,
        store=store,
        actor=actor,
    )
    signature = finding_signature_from_report_data(evaluation.report)
    snapshot = store.get_snapshot(snapshot_id)
    if snapshot is None:
        if not create_snapshot:
            drift = store.save_drift_check(
                DriftCheck(
                    snapshot_id=snapshot_id,
                    drifted=True,
                    status="changed",
                    added=signature,
                ),
                actor=actor,
            )
        else:
            store.save_snapshot(
                DriftSnapshot(id=snapshot_id, signature=signature, report=evaluation.report)
            )
            drift = store.save_drift_check(
                DriftCheck(
                    snapshot_id=snapshot_id,
                    drifted=False,
                    status="baseline_created",
                ),
                actor=actor,
            )
    else:
        current = set(signature)
        previous = set(snapshot.signature)
        added = sorted(current - previous)
        removed = sorted(previous - current)
        drifted = bool(added or removed)
        if update_snapshot:
            store.save_snapshot(
                DriftSnapshot(id=snapshot_id, signature=signature, report=evaluation.report)
            )
        drift = store.save_drift_check(
            DriftCheck(
                snapshot_id=snapshot_id,
                drifted=drifted,
                status="changed" if drifted else "matched",
                added=added,
                removed=removed,
            ),
            actor=actor,
        )

    reasons: list[str] = []
    decision = evaluation.decision
    if evaluation.decision == "block":
        reasons.append("evaluation_blocked")
    if drift.drifted:
        decision = "block"
        reasons.append("drift_changed")
    elif drift.status == "baseline_created":
        reasons.append("snapshot_created")
    if evaluation.decision == "warn" and decision != "block":
        reasons.append("evaluation_warned")

    evidence = None
    if export_format:
        evidence = export_evidence(
            evaluation.id,
            format=export_format,
            store=store,
            actor=actor,
        )
    result = DriftGateResult(
        decision=decision,
        evaluation=evaluation,
        drift=drift,
        evidence=evidence,
        reasons=reasons,
    )
    return store.save_drift_gate(result, actor=actor)


def preview_policy(
    policy_id: str,
    path: Path | str,
    state_path: Path | str | None = None,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> PolicyPreviewResult:
    store = store or EnterpriseStore()
    policy = store.get_policy(policy_id)
    report = scan_path(Path(path), state_path=state_path)
    enrich_report_findings(report, store, policy_ids=[policy.id])
    matching_findings = [
        finding.model_dump(mode="json")
        for finding in report.findings
        if policy.rule_id and finding.rule_id == policy.rule_id
    ]
    summary = _preview_summary(matching_findings)
    result = PolicyPreviewResult(
        policy_id=policy.id,
        policy_name=policy.name,
        rule_id=policy.rule_id,
        scanned_path=str(path),
        findings=matching_findings,
        summary=summary,
    )
    return store.save_policy_preview(result, actor=actor)


def finding_signature(report: ScanReport) -> list[str]:
    return sorted(
        f"{finding.rule_id}|{finding.severity}|{finding.path or ''}|{finding.message}"
        for finding in report.findings
    )


def _preview_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "findings": len(findings),
        "high": sum(1 for finding in findings if finding.get("severity") == "high"),
        "medium": sum(1 for finding in findings if finding.get("severity") == "medium"),
        "low": sum(1 for finding in findings if finding.get("severity") == "low"),
    }


def finding_signature_from_report_data(report: dict[str, Any]) -> list[str]:
    return sorted(
        f"{finding.get('rule_id')}|{finding.get('severity')}|"
        f"{finding.get('path') or ''}|{finding.get('message')}"
        for finding in report.get("findings", [])
    )


def _resolved_binding_targets(
    bindings: list[GroupPolicyBinding],
    context: EvaluationContext,
) -> set[tuple[str, str]]:
    direct_targets = [
        ("org", context.org),
        ("group", context.group),
        ("repo", context.repo),
    ]
    targets = {
        (target_type, target)
        for target_type, target in direct_targets
        if target
    }
    parent_by_target = {
        (binding.target_type, binding.target): binding.parent
        for binding in bindings
        if binding.parent
    }
    seen: set[tuple[str, str]] = set()
    queue = list(targets)
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        parent = parent_by_target.get(current)
        if not parent:
            continue
        for binding in bindings:
            if binding.target == parent:
                parent_target = (binding.target_type, binding.target)
                targets.add(parent_target)
                queue.append(parent_target)
        if context.org == parent:
            parent_target = ("org", parent)
            targets.add(parent_target)
            queue.append(parent_target)
    return targets


def _primary_context_target(
    context: EvaluationContext,
) -> tuple[Literal["org", "group", "repo"], str]:
    if context.repo:
        return "repo", context.repo
    if context.group:
        return "group", context.group
    if context.org:
        return "org", context.org
    if context.baseline:
        return "org", context.baseline
    return "org", "default"


def _replace_evaluation(store: EnterpriseStore, result: EvaluationResult) -> None:
    results = [EvaluationResult.model_validate(item) for item in store._read_list("evaluations")]
    for idx, current in enumerate(results):
        if current.id == result.id:
            results[idx] = result
            store._write_models("evaluations", results)
            return


def _findings_at_or_above(report: ScanReport, level: str) -> bool:
    threshold = SEVERITY_ORDER[level]
    return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in report.findings)


def _policy_exists(store: EnterpriseStore, policy_id: str) -> bool:
    try:
        store.get_policy(policy_id)
    except KeyError:
        return False
    return True


def _write_evidence_csv(path: Path, result: EvaluationResult) -> None:
    findings = result.report.get("findings", [])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "result_id",
                "decision",
                "rule_id",
                "severity",
                "message",
                "path",
                "owner",
                "standard",
                "control_id",
                "risk",
                "remediation",
            ],
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow(
                {
                    "result_id": result.id,
                    "decision": result.decision,
                    "rule_id": finding.get("rule_id"),
                    "severity": finding.get("severity"),
                    "message": finding.get("message"),
                    "path": finding.get("path"),
                    "owner": finding.get("owner"),
                    "standard": finding.get("standard"),
                    "control_id": finding.get("control_id"),
                    "risk": finding.get("risk"),
                    "remediation": finding.get("remediation"),
                }
            )


def _write_evidence_pdf(path: Path, result: EvaluationResult) -> None:
    lines = _evidence_pdf_lines(result)
    content_lines = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
    for line in lines[:48]:
        content_lines.append(f"({_pdf_escape(line)}) Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (
            b"<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        ),
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{idx} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_start = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n"
        ).encode("ascii")
    )
    path.write_bytes(bytes(output))


def _evidence_pdf_lines(result: EvaluationResult) -> list[str]:
    report = result.report
    summary = report.get("summary", {})
    context = result.context
    lines = [
        "Terraform Guardrail Evidence Report",
        f"Result ID: {result.id}",
        f"Created At: {result.created_at}",
        f"Decision: {result.decision.upper()}",
        f"Provider: {context.provider or 'n/a'}",
        f"Baseline: {context.baseline or 'n/a'}",
        f"Environment: {context.environment or 'n/a'}",
        f"Org: {context.org or 'n/a'}",
        f"Group: {context.group or 'n/a'}",
        f"Repo: {context.repo or 'n/a'}",
        f"Resolved Policies: {', '.join(result.resolved_policy_ids) or 'none'}",
        "",
        "Summary",
        f"Scanned Path: {report.get('scanned_path', 'n/a')}",
        f"Findings: {summary.get('findings', 0)}",
        f"High: {summary.get('high', 0)}",
        f"Medium: {summary.get('medium', 0)}",
        f"Low: {summary.get('low', 0)}",
        "",
        "Findings",
    ]
    findings = report.get("findings", [])
    if not findings:
        lines.append("No findings detected.")
    for finding in findings[:20]:
        lines.extend(
            [
                f"{finding.get('rule_id')} [{finding.get('severity')}] {finding.get('message')}",
                f"Path: {finding.get('path') or 'n/a'}",
                f"Owner: {finding.get('owner') or 'n/a'}",
                f"Standard: {finding.get('standard') or 'n/a'}",
                f"Control: {finding.get('control_id') or 'n/a'}",
                f"Risk: {finding.get('risk') or 'n/a'}",
                f"Remediation: {finding.get('remediation') or 'n/a'}",
                "",
            ]
        )
    return [_truncate_pdf_line(line) for line in lines]


def _truncate_pdf_line(line: str) -> str:
    return line if len(line) <= 95 else line[:92] + "..."


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
