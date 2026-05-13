from __future__ import annotations

import csv
import json
import os
import uuid
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Literal
from xml.etree import ElementTree as ET

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


class PolicyWaiver(BaseModel):
    id: str = Field(default_factory=lambda: new_id("waiver"))
    rule_id: str
    reason: str
    owner: str
    expires_at: str
    path: str | None = None
    policy_id: str | None = None
    target_type: Literal["org", "group", "repo", "app"] | None = None
    target: str | None = None
    status: Literal["requested", "approved", "revoked"] = "requested"
    requested_by: str = "system"
    approved_by: str | None = None
    revoked_by: str | None = None
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


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
    risk_tier: str | None = None
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


class RiskProfile(BaseModel):
    id: str = Field(default_factory=lambda: new_id("risk"))
    name: str
    description: str = ""
    environments: list[str] = Field(default_factory=list)
    risk_tiers: list[str] = Field(default_factory=list)
    rule_severity_overrides: dict[str, Literal["low", "medium", "high"]] = Field(
        default_factory=dict
    )
    default_fail_on: Literal["low", "medium", "high"] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class Recommendation(BaseModel):
    rule_id: str
    title: str
    remediation: str
    suggested_fix: str
    severity: Literal["low", "medium", "high"] | None = None
    references: list[str] = Field(default_factory=list)


class FindingExplanation(BaseModel):
    rule_id: str
    severity: Literal["low", "medium", "high"]
    message: str
    path: str | None = None
    policy_id: str | None = None
    policy_name: str | None = None
    policy_status: str | None = None
    baseline_ids: list[str] = Field(default_factory=list)
    context_adjustment: dict[str, Any] | None = None
    waiver_id: str | None = None
    waiver_expires_at: str | None = None
    remediation: str | None = None
    suggested_fix: str | None = None
    reason: str


class ExplainabilityReport(BaseModel):
    id: str = Field(default_factory=lambda: new_id("explain"))
    result_id: str
    created_at: str = Field(default_factory=utc_now)
    decision: Literal["pass", "warn", "block"]
    summary: dict[str, Any] = Field(default_factory=dict)
    context: EvaluationContext = Field(default_factory=EvaluationContext)
    reasons: list[str] = Field(default_factory=list)
    applied_policy_ids: list[str] = Field(default_factory=list)
    applied_policies: list[dict[str, Any]] = Field(default_factory=list)
    binding_targets: list[str] = Field(default_factory=list)
    baseline_ids: list[str] = Field(default_factory=list)
    risk_profile: dict[str, Any] | None = None
    context_adjustments: list[dict[str, Any]] = Field(default_factory=list)
    applied_waivers: list[dict[str, Any]] = Field(default_factory=list)
    finding_explanations: list[FindingExplanation] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)


class RemediationAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fix"))
    rule_id: str
    severity: Literal["low", "medium", "high"]
    path: str | None = None
    message: str = ""
    suggested_fix: str
    patch_type: Literal["manual", "terraform_snippet"] = "manual"
    patch_preview: str = ""
    confidence: Literal["low", "medium", "high"] = "medium"
    requires_review: bool = True
    waiver_id: str | None = None


class RemediationPlan(BaseModel):
    id: str = Field(default_factory=lambda: new_id("remed"))
    result_id: str
    created_at: str = Field(default_factory=utc_now)
    decision: Literal["pass", "warn", "block"]
    summary: dict[str, Any] = Field(default_factory=dict)
    actions: list[RemediationAction] = Field(default_factory=list)
    skipped: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GovernanceHealthReport(BaseModel):
    id: str = Field(default_factory=lambda: new_id("health"))
    created_at: str = Field(default_factory=utc_now)
    window: str = "all"
    totals: dict[str, Any] = Field(default_factory=dict)
    decisions: dict[str, int] = Field(default_factory=dict)
    top_rules: list[dict[str, Any]] = Field(default_factory=list)
    waiver_summary: dict[str, Any] = Field(default_factory=dict)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    risk_signals: list[str] = Field(default_factory=list)


class ScheduledScanTarget(BaseModel):
    id: str = Field(default_factory=lambda: new_id("sched"))
    name: str
    path: str
    cadence: Literal["hourly", "daily", "weekly", "monthly"] = "daily"
    enabled: bool = True
    state_path: str | None = None
    provider: str | None = None
    baseline: str | None = None
    policy_set: str | None = None
    fail_on: Literal["low", "medium", "high"] | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)


class ScheduledScanRun(BaseModel):
    id: str = Field(default_factory=lambda: new_id("sched_run"))
    target_id: str
    target_name: str
    created_at: str = Field(default_factory=utc_now)
    status: Literal["completed", "failed"]
    result_id: str | None = None
    decision: Literal["pass", "warn", "block"] | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


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

    def list_waivers(self) -> list[PolicyWaiver]:
        return [PolicyWaiver.model_validate(item) for item in self._read_list("waivers")]

    def get_waiver(self, waiver_id: str) -> PolicyWaiver:
        for waiver in self.list_waivers():
            if waiver.id == waiver_id:
                return waiver
        raise KeyError(f"Waiver not found: {waiver_id}")

    def save_waiver(self, waiver: PolicyWaiver, actor: str = "system") -> PolicyWaiver:
        waivers = self.list_waivers()
        for idx, current in enumerate(waivers):
            if current.id == waiver.id:
                waiver.updated_at = utc_now()
                waivers[idx] = waiver
                self._write_models("waivers", waivers)
                self.add_audit(actor, "waiver.update", waiver.id, waiver.model_dump())
                return waiver
        waivers.append(waiver)
        self._write_models("waivers", waivers)
        self.add_audit(actor, "waiver.request", waiver.id, waiver.model_dump())
        return waiver

    def approve_waiver(self, waiver_id: str, actor: str = "system") -> PolicyWaiver:
        waiver = self.get_waiver(waiver_id)
        waiver.status = "approved"
        waiver.approved_by = actor
        waiver.updated_at = utc_now()
        saved = self.save_waiver(waiver, actor=actor)
        self.add_audit(actor, "waiver.approve", waiver.id, waiver.model_dump())
        return saved

    def revoke_waiver(self, waiver_id: str, actor: str = "system") -> PolicyWaiver:
        waiver = self.get_waiver(waiver_id)
        waiver.status = "revoked"
        waiver.revoked_by = actor
        waiver.updated_at = utc_now()
        saved = self.save_waiver(waiver, actor=actor)
        self.add_audit(actor, "waiver.revoke", waiver.id, waiver.model_dump())
        return saved

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

    def list_risk_profiles(self) -> list[RiskProfile]:
        stored = [RiskProfile.model_validate(item) for item in self._read_list("risk_profiles")]
        return stored or default_risk_profiles()

    def get_risk_profile(self, profile_id_or_name: str) -> RiskProfile:
        for profile in self.list_risk_profiles():
            if profile.id == profile_id_or_name or profile.name == profile_id_or_name:
                return profile
        raise KeyError(f"Risk profile not found: {profile_id_or_name}")

    def save_risk_profile(
        self,
        profile: RiskProfile,
        actor: str = "system",
    ) -> RiskProfile:
        profiles = [
            RiskProfile.model_validate(item) for item in self._read_list("risk_profiles")
        ]
        for idx, current in enumerate(profiles):
            if current.id == profile.id:
                profile.updated_at = utc_now()
                profiles[idx] = profile
                self._write_models("risk_profiles", profiles)
                self.add_audit(actor, "risk_profile.update", profile.id, profile.model_dump())
                return profile
        profiles.append(profile)
        self._write_models("risk_profiles", profiles)
        self.add_audit(actor, "risk_profile.create", profile.id, profile.model_dump())
        return profile

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

    def list_evaluations(self) -> list[EvaluationResult]:
        return [
            EvaluationResult.model_validate(item)
            for item in self._read_list("evaluations")
        ]

    def save_remediation_plan(
        self,
        plan: RemediationPlan,
        actor: str = "system",
    ) -> RemediationPlan:
        plans = [
            RemediationPlan.model_validate(item)
            for item in self._read_list("remediation_plans")
        ]
        plans.append(plan)
        self._write_models("remediation_plans", plans)
        self.add_audit(
            actor,
            "remediation.plan.create",
            plan.id,
            {"result_id": plan.result_id, "actions": len(plan.actions)},
        )
        return plan

    def get_remediation_plan(self, plan_id: str) -> RemediationPlan:
        for plan in self._read_list("remediation_plans"):
            if plan.get("id") == plan_id:
                return RemediationPlan.model_validate(plan)
        raise KeyError(f"Remediation plan not found: {plan_id}")

    def list_remediation_plans(self, result_id: str | None = None) -> list[RemediationPlan]:
        plans = [
            RemediationPlan.model_validate(item)
            for item in self._read_list("remediation_plans")
        ]
        if result_id:
            plans = [plan for plan in plans if plan.result_id == result_id]
        return plans

    def list_scheduled_scan_targets(self) -> list[ScheduledScanTarget]:
        return [
            ScheduledScanTarget.model_validate(item)
            for item in self._read_list("scheduled_scan_targets")
        ]

    def get_scheduled_scan_target(self, target_id: str) -> ScheduledScanTarget:
        for target in self.list_scheduled_scan_targets():
            if target.id == target_id:
                return target
        raise KeyError(f"Scheduled scan target not found: {target_id}")

    def save_scheduled_scan_target(
        self,
        target: ScheduledScanTarget,
        actor: str = "system",
    ) -> ScheduledScanTarget:
        targets = self.list_scheduled_scan_targets()
        for idx, current in enumerate(targets):
            if current.id == target.id:
                target.updated_at = utc_now()
                targets[idx] = target
                self._write_models("scheduled_scan_targets", targets)
                self.add_audit(actor, "scheduled_scan.update", target.id, target.model_dump())
                return target
        targets.append(target)
        self._write_models("scheduled_scan_targets", targets)
        self.add_audit(actor, "scheduled_scan.create", target.id, target.model_dump())
        return target

    def list_scheduled_scan_runs(self, target_id: str | None = None) -> list[ScheduledScanRun]:
        runs = [
            ScheduledScanRun.model_validate(item)
            for item in self._read_list("scheduled_scan_runs")
        ]
        if target_id:
            runs = [run for run in runs if run.target_id == target_id]
        return runs

    def save_scheduled_scan_run(
        self,
        run: ScheduledScanRun,
        actor: str = "system",
    ) -> ScheduledScanRun:
        runs = self.list_scheduled_scan_runs()
        runs.append(run)
        self._write_models("scheduled_scan_runs", runs)
        self.add_audit(
            actor,
            "scheduled_scan.run",
            run.id,
            {
                "target_id": run.target_id,
                "status": run.status,
                "result_id": run.result_id,
                "decision": run.decision,
            },
        )
        return run

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


def default_risk_profiles() -> list[RiskProfile]:
    return [
        RiskProfile(
            id="default-prod-high-risk",
            name="Production high-risk",
            description=(
                "Stricter context for production or high-risk workloads. "
                "Encryption, public exposure, and ownership issues are treated as higher impact."
            ),
            environments=["prod", "production"],
            risk_tiers=["high", "critical"],
            rule_severity_overrides={
                "TG010": "high",
                "TG011": "high",
                "TG012": "high",
                "TG013": "high",
                "TG016": "medium",
                "TG019": "high",
                "TG020": "high",
                "TG022": "high",
                "TG023": "medium",
            },
            default_fail_on="high",
        ),
        RiskProfile(
            id="default-dev-sandbox",
            name="Development sandbox",
            description="Lenient context for early development and sandbox experimentation.",
            environments=["dev", "development", "sandbox"],
            risk_tiers=["low"],
            default_fail_on="high",
        ),
    ]


def list_rule_recommendations() -> list[Recommendation]:
    return [
        Recommendation(
            rule_id=rule_id,
            title=f"Fix {rule_id}",
            remediation=str(metadata.get("remediation") or ""),
            suggested_fix=_suggested_fix_for_rule(rule_id, str(metadata.get("remediation") or "")),
            severity=_metadata_severity(rule_id),
        )
        for rule_id, metadata in RULE_METADATA.items()
    ]


def get_rule_recommendation(rule_id: str) -> Recommendation:
    for recommendation in list_rule_recommendations():
        if recommendation.rule_id == rule_id:
            return recommendation
    raise KeyError(f"Recommendation not found: {rule_id}")


def explain_evaluation(
    result_id: str,
    store: EnterpriseStore | None = None,
) -> ExplainabilityReport:
    store = store or EnterpriseStore()
    result = store.get_evaluation(result_id)
    resolved = resolve_policy_set(store, result.context)
    policies_by_id = {
        policy.id: policy
        for policy in (
            store.get_policy(policy_id)
            for policy_id in result.resolved_policy_ids
            if _policy_exists(store, policy_id)
        )
    }
    intelligence = result.service_metadata.get("intelligence", {})
    waivers = result.service_metadata.get("waivers", {})
    adjustments = intelligence.get("adjustments", [])
    adjustment_by_rule_path = {
        (item.get("rule_id"), item.get("path")): item
        for item in adjustments
        if isinstance(item, dict)
    }
    explanations = [
        _explain_finding(
            finding,
            policies_by_id,
            resolved.baseline_ids,
            adjustment_by_rule_path,
        )
        for finding in result.report.get("findings", [])
    ]
    reasons = _decision_reasons(result, explanations)
    return ExplainabilityReport(
        result_id=result.id,
        decision=result.decision,
        summary=result.report.get("summary", {}),
        context=result.context,
        reasons=reasons,
        applied_policy_ids=result.resolved_policy_ids,
        applied_policies=[
            _policy_explain_payload(policy)
            for policy in policies_by_id.values()
        ],
        binding_targets=resolved.binding_targets,
        baseline_ids=resolved.baseline_ids,
        risk_profile=intelligence.get("profile"),
        context_adjustments=[
            item for item in adjustments if isinstance(item, dict)
        ],
        applied_waivers=[
            item for item in waivers.get("applied", []) if isinstance(item, dict)
        ],
        finding_explanations=explanations,
        next_actions=_next_actions(result, explanations),
    )


def render_explanation_markdown(report: ExplainabilityReport) -> str:
    icon = {"pass": "PASS", "warn": "WARN", "block": "BLOCK"}[report.decision]
    lines = [
        "## Terraform Guardrail Evaluation",
        "",
        f"**Decision:** `{icon}`",
        f"**Result ID:** `{report.result_id}`",
        "",
        "### Summary",
        "",
        "| Total | High | Medium | Low |",
        "| ---: | ---: | ---: | ---: |",
        (
            f"| {report.summary.get('findings', 0)} | {report.summary.get('high', 0)} | "
            f"{report.summary.get('medium', 0)} | {report.summary.get('low', 0)} |"
        ),
        "",
    ]
    if report.risk_profile:
        lines.extend(
            [
                "### Context",
                "",
                f"- Risk profile: `{report.risk_profile.get('name')}`",
                f"- Environment: `{report.context.environment or 'not set'}`",
                f"- Risk tier: `{report.context.risk_tier or 'not set'}`",
                "",
            ]
        )
    if report.reasons:
        lines.extend(["### Why", ""])
        lines.extend(f"- {reason}" for reason in report.reasons)
        lines.append("")
    if report.applied_waivers:
        lines.extend(["### Approved Waivers", ""])
        for waiver in report.applied_waivers:
            lines.append(
                f"- `{waiver.get('rule_id')}` waived by `{waiver.get('waiver_id')}` "
                f"until `{waiver.get('expires_at')}`"
            )
        lines.append("")
    if report.finding_explanations:
        lines.extend(
            [
                "### Findings",
                "",
                "| Rule | Severity | Path | Explanation | Suggested Fix |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in report.finding_explanations[:10]:
            lines.append(
                "| "
                f"`{_md_escape(finding.rule_id)}` | "
                f"`{_md_escape(finding.severity)}` | "
                f"{_md_escape(finding.path or 'n/a')} | "
                f"{_md_escape(finding.reason)} | "
                f"{_md_escape(finding.suggested_fix or finding.remediation or 'Review finding.')} |"
            )
        if len(report.finding_explanations) > 10:
            lines.append(
                f"| ... | ... | ... | {len(report.finding_explanations) - 10} more findings | ... |"
            )
        lines.append("")
    if report.next_actions:
        lines.extend(["### Next Actions", ""])
        lines.extend(f"- {action}" for action in report.next_actions[:8])
        lines.append("")
    if report.applied_policy_ids or report.baseline_ids:
        lines.extend(["### Enforcement Context", ""])
        if report.baseline_ids:
            lines.append(f"- Baselines: `{', '.join(report.baseline_ids)}`")
        if report.applied_policy_ids:
            lines.append(f"- Policies: `{', '.join(report.applied_policy_ids)}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_evaluation_sarif(result: EvaluationResult) -> dict[str, Any]:
    findings = result.report.get("findings", [])
    rules_by_id: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "TG000")
        rules_by_id.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(finding.get("message") or rule_id)},
                "help": {
                    "text": str(
                        finding.get("suggested_fix")
                        or finding.get("remediation")
                        or "Review the Terraform Guardrail finding."
                    )
                },
                "properties": {
                    "severity": finding.get("severity"),
                    "risk": finding.get("risk"),
                    "standard": finding.get("standard"),
                    "control_id": finding.get("control_id"),
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(str(finding.get("severity") or "low")),
                "message": {"text": str(finding.get("message") or "")},
                "locations": [
                    _sarif_location(str(finding.get("path") or result.report["scanned_path"]))
                ],
                "properties": {
                    "decision": result.decision,
                    "owner": finding.get("owner"),
                    "remediation": finding.get("remediation"),
                    "suggested_fix": finding.get("suggested_fix"),
                    "waiver_id": finding.get("waiver_id"),
                    "waiver_expires_at": finding.get("waiver_expires_at"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Terraform Guardrail",
                        "informationUri": "https://github.com/Huzefaaa2/terraform-guardrail",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": result.decision != "block",
                        "properties": {
                            "evaluation_id": result.id,
                            "decision": result.decision,
                            "resolved_policy_ids": result.resolved_policy_ids,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def render_evaluation_junit(result: EvaluationResult) -> str:
    findings = result.report.get("findings", [])
    failures = [
        finding
        for finding in findings
        if finding.get("severity") == "high" and not _finding_is_waived(finding)
    ]
    testsuite = ET.Element(
        "testsuite",
        {
            "name": "terraform-guardrail-enterprise",
            "tests": str(max(len(findings), 1)),
            "failures": str(len(failures)),
            "errors": "0",
            "skipped": "0",
            "timestamp": result.created_at,
        },
    )
    if not findings:
        ET.SubElement(
            testsuite,
            "testcase",
            {"classname": "terraform_guardrail", "name": f"evaluation-{result.id}"},
        )
    for finding in findings:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": str(finding.get("rule_id") or "terraform_guardrail"),
                "name": str(finding.get("path") or finding.get("message") or "finding"),
            },
        )
        if finding.get("severity") == "high" and not _finding_is_waived(finding):
            failure = ET.SubElement(
                testcase,
                "failure",
                {
                    "message": str(finding.get("message") or ""),
                    "type": str(finding.get("rule_id") or "finding"),
                },
            )
            failure.text = str(
                finding.get("suggested_fix")
                or finding.get("remediation")
                or "Review the Terraform Guardrail finding."
            )
        else:
            system_out = ET.SubElement(testcase, "system-out")
            system_out.text = str(
                f"Waived until {finding.get('waiver_expires_at')}. "
                if _finding_is_waived(finding)
                else ""
            ) + str(
                finding.get("suggested_fix")
                or finding.get("remediation")
                or finding.get("message")
                or ""
            )
    return ET.tostring(testsuite, encoding="unicode")


def render_evaluation_report(
    result_id: str,
    format: Literal["sarif", "junit"],
    store: EnterpriseStore | None = None,
) -> str:
    store = store or EnterpriseStore()
    result = store.get_evaluation(result_id)
    if format == "sarif":
        return json.dumps(render_evaluation_sarif(result), indent=2)
    if format == "junit":
        return render_evaluation_junit(result)
    raise ValueError("Report format must be sarif or junit.")


def create_remediation_plan(
    result_id: str,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> RemediationPlan:
    store = store or EnterpriseStore()
    result = store.get_evaluation(result_id)
    actions: list[RemediationAction] = []
    skipped: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for finding in result.report.get("findings", []):
        rule_id = str(finding.get("rule_id") or "TG000")
        path = finding.get("path")
        key = (rule_id, path if isinstance(path, str) else None)
        if key in seen:
            continue
        seen.add(key)
        if _finding_is_waived(finding):
            skipped.append(
                {
                    "rule_id": rule_id,
                    "path": path,
                    "reason": "approved waiver is active",
                    "waiver_id": finding.get("waiver_id"),
                }
            )
            continue
        suggested_fix = str(
            finding.get("suggested_fix")
            or finding.get("remediation")
            or _suggested_fix_for_rule(rule_id, "Review and remediate this finding.")
        )
        patch_preview = _remediation_patch_preview(rule_id, finding)
        actions.append(
            RemediationAction(
                rule_id=rule_id,
                severity=(
                    finding.get("severity")
                    if finding.get("severity") in SEVERITY_ORDER
                    else "low"
                ),
                path=path if isinstance(path, str) else None,
                message=str(finding.get("message") or ""),
                suggested_fix=suggested_fix,
                patch_type="terraform_snippet" if patch_preview else "manual",
                patch_preview=patch_preview,
                confidence=_remediation_confidence(rule_id, patch_preview),
            )
        )
    plan = RemediationPlan(
        result_id=result.id,
        decision=result.decision,
        summary=result.report.get("summary", {}),
        actions=actions,
        skipped=skipped,
        metadata={
            "source": "v5-autonomous-governance",
            "scanned_path": result.report.get("scanned_path"),
            "context": result.context.model_dump(mode="json"),
        },
    )
    return store.save_remediation_plan(plan, actor=actor)


def render_remediation_markdown(plan: RemediationPlan) -> str:
    lines = [
        "## Terraform Guardrail Remediation Plan",
        "",
        f"**Plan ID:** `{plan.id}`",
        f"**Result ID:** `{plan.result_id}`",
        f"**Decision:** `{plan.decision.upper()}`",
        "",
        "### Summary",
        "",
        "| Actions | Skipped | High | Medium | Low |",
        "| ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {len(plan.actions)} | {len(plan.skipped)} | "
            f"{plan.summary.get('high', 0)} | {plan.summary.get('medium', 0)} | "
            f"{plan.summary.get('low', 0)} |"
        ),
        "",
    ]
    if plan.actions:
        lines.extend(["### Actions", ""])
        for action in plan.actions:
            lines.extend(
                [
                    f"#### {action.rule_id} - {action.severity}",
                    "",
                    f"- Path: `{action.path or 'n/a'}`",
                    f"- Fix: {action.suggested_fix}",
                    f"- Confidence: `{action.confidence}`",
                ]
            )
            if action.patch_preview:
                lines.extend(["", "```hcl", action.patch_preview.rstrip(), "```"])
            lines.append("")
    if plan.skipped:
        lines.extend(["### Skipped", ""])
        for item in plan.skipped:
            lines.append(
                f"- `{item.get('rule_id')}` at `{item.get('path') or 'n/a'}`: "
                f"{item.get('reason')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def governance_health_report(
    store: EnterpriseStore | None = None,
    window: str = "all",
) -> GovernanceHealthReport:
    store = store or EnterpriseStore()
    evaluations = store.list_evaluations()
    decisions = {"pass": 0, "warn": 0, "block": 0}
    rule_counts: dict[str, dict[str, Any]] = {}
    total_findings = 0
    for evaluation in evaluations:
        decisions[evaluation.decision] += 1
        for finding in evaluation.report.get("findings", []):
            rule_id = str(finding.get("rule_id") or "TG000")
            total_findings += 1
            bucket = rule_counts.setdefault(
                rule_id,
                {"rule_id": rule_id, "count": 0, "high": 0, "medium": 0, "low": 0},
            )
            bucket["count"] += 1
            severity = finding.get("severity")
            if severity in {"high", "medium", "low"}:
                bucket[severity] += 1
    waivers = store.list_waivers()
    exports = [EvidenceExport.model_validate(item) for item in store._read_list("exports")]
    active_waivers = [
        waiver for waiver in waivers if waiver.status == "approved" and _waiver_is_active(waiver)
    ]
    risk_signals = _governance_risk_signals(decisions, total_findings, active_waivers, exports)
    return GovernanceHealthReport(
        window=window,
        totals={
            "evaluations": len(evaluations),
            "findings": total_findings,
            "policies": len(store.list_policies()),
            "baselines": len(store.list_baselines()),
            "remediation_plans": len(store.list_remediation_plans()),
            "scheduled_targets": len(store.list_scheduled_scan_targets()),
            "scheduled_runs": len(store.list_scheduled_scan_runs()),
        },
        decisions=decisions,
        top_rules=sorted(rule_counts.values(), key=lambda item: item["count"], reverse=True)[:10],
        waiver_summary={
            "total": len(waivers),
            "active": len(active_waivers),
            "requested": sum(1 for waiver in waivers if waiver.status == "requested"),
            "revoked": sum(1 for waiver in waivers if waiver.status == "revoked"),
        },
        evidence_summary={
            "exports": len(exports),
            "formats": _count_by([export.format for export in exports]),
        },
        risk_signals=risk_signals,
    )


def run_scheduled_scan(
    target_id: str,
    store: EnterpriseStore | None = None,
    actor: str = "system",
) -> ScheduledScanRun:
    store = store or EnterpriseStore()
    target = store.get_scheduled_scan_target(target_id)
    if not target.enabled:
        run = ScheduledScanRun(
            target_id=target.id,
            target_name=target.name,
            status="failed",
            error="Scheduled scan target is disabled.",
        )
        return store.save_scheduled_scan_run(run, actor=actor)
    try:
        result = evaluate_enterprise(
            path=target.path,
            state_path=target.state_path,
            provider=target.provider,
            policy_set=target.policy_set,
            baseline=target.baseline,
            context=target.context,
            fail_on=target.fail_on,
            store=store,
            actor=actor,
            service_metadata={
                "scheduled_scan_target_id": target.id,
                "scheduled_scan_target_name": target.name,
                "scheduled_scan_cadence": target.cadence,
            },
        )
        run = ScheduledScanRun(
            target_id=target.id,
            target_name=target.name,
            status="completed",
            result_id=result.id,
            decision=result.decision,
            summary=result.report.get("summary", {}),
        )
    except Exception as exc:  # noqa: BLE001
        run = ScheduledScanRun(
            target_id=target.id,
            target_name=target.name,
            status="failed",
            error=str(exc),
        )
    return store.save_scheduled_scan_run(run, actor=actor)


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
        for key in ("environment", "risk_tier", "app", "org", "group", "repo"):
            if key in context:
                setattr(ctx, key, context[key])
        ctx.extra = {key: value for key, value in context.items() if not hasattr(ctx, key)}

    report = scan_path(Path(path), state_path=state_path)
    resolved_policy_ids = resolve_policy_ids(store, ctx)
    enrich_report_findings(report, store, resolved_policy_ids)
    intelligence = apply_contextual_intelligence(report, store, ctx)
    waiver_metadata = apply_active_waivers(report, store, ctx)
    effective_fail_on = fail_on or intelligence.get("default_fail_on")
    decision = decide(report, resolved_policy_ids, store, fail_on=effective_fail_on)
    metadata = service_metadata or {}
    metadata = {**metadata, "intelligence": intelligence, "waivers": waiver_metadata}
    result = EvaluationResult(
        request_id=request_id,
        decision=decision,
        context=ctx,
        resolved_policy_ids=resolved_policy_ids,
        report=report.model_dump(mode="json"),
        service_metadata=metadata,
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
        if finding.remediation:
            finding.suggested_fix = _suggested_fix_for_rule(finding.rule_id, finding.remediation)
        detail = finding.detail or {}
        if policy:
            detail.setdefault("policy_id", policy.id)
            detail.setdefault("policy_status", policy.status)
        if rule_metadata:
            detail.setdefault("default_risk", rule_metadata.get("risk"))
            detail.setdefault("recommendation", rule_metadata.get("remediation"))
        if finding.suggested_fix:
            detail.setdefault("suggested_fix", finding.suggested_fix)
        finding.detail = detail


def apply_contextual_intelligence(
    report: ScanReport,
    store: EnterpriseStore,
    context: EvaluationContext,
) -> dict[str, Any]:
    profile = resolve_risk_profile(store, context)
    adjustments: list[dict[str, Any]] = []
    for finding in report.findings:
        original = finding.severity
        target = profile.rule_severity_overrides.get(finding.rule_id) if profile else None
        if target and SEVERITY_ORDER[target] > SEVERITY_ORDER[original]:
            finding.severity = target
            detail = finding.detail or {}
            detail["context_severity"] = {
                "from": original,
                "to": target,
                "profile": profile.name,
            }
            finding.detail = detail
            adjustments.append(
                {
                    "rule_id": finding.rule_id,
                    "path": finding.path,
                    "from": original,
                    "to": target,
                    "profile": profile.name,
                }
            )
    if adjustments:
        report.summary.high = sum(1 for finding in report.findings if finding.severity == "high")
        report.summary.medium = sum(
            1 for finding in report.findings if finding.severity == "medium"
        )
        report.summary.low = sum(1 for finding in report.findings if finding.severity == "low")
    recommendations = [
        {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "severity": finding.severity,
            "remediation": finding.remediation,
            "suggested_fix": finding.suggested_fix,
        }
        for finding in report.findings
        if finding.suggested_fix
    ]
    intelligence = {
        "context": {
            "environment": context.environment,
            "risk_tier": context.risk_tier,
            "app": context.app,
            "org": context.org,
            "group": context.group,
            "repo": context.repo,
        },
        "profile": profile.model_dump(mode="json") if profile else None,
        "adjustments": adjustments,
        "recommendations": recommendations,
    }
    if profile and profile.default_fail_on:
        intelligence["default_fail_on"] = profile.default_fail_on
    report.metadata["intelligence"] = intelligence
    return intelligence


def resolve_risk_profile(
    store: EnterpriseStore,
    context: EvaluationContext,
) -> RiskProfile | None:
    explicit = context.extra.get("risk_profile") or context.extra.get("risk_profile_id")
    if explicit:
        try:
            return store.get_risk_profile(str(explicit))
        except KeyError:
            return None
    environment = (context.environment or "").lower()
    risk_tier = (context.risk_tier or str(context.extra.get("risk_tier") or "")).lower()
    best: tuple[int, RiskProfile] | None = None
    for profile in store.list_risk_profiles():
        score = 0
        if environment and environment in {item.lower() for item in profile.environments}:
            score += 2
        if risk_tier and risk_tier in {item.lower() for item in profile.risk_tiers}:
            score += 2
        if not environment and not risk_tier:
            continue
        if score and (best is None or score > best[0]):
            best = (score, profile)
    return best[1] if best else None


def apply_active_waivers(
    report: ScanReport,
    store: EnterpriseStore,
    context: EvaluationContext,
) -> dict[str, Any]:
    active = [
        waiver
        for waiver in store.list_waivers()
        if waiver.status == "approved" and _waiver_is_active(waiver)
    ]
    applied: list[dict[str, Any]] = []
    for finding in report.findings:
        for waiver in active:
            if not _waiver_matches_finding(waiver, finding.model_dump(mode="json"), context):
                continue
            finding.waiver_id = waiver.id
            finding.waiver_expires_at = waiver.expires_at
            detail = finding.detail or {}
            detail["waiver"] = {
                "id": waiver.id,
                "owner": waiver.owner,
                "reason": waiver.reason,
                "expires_at": waiver.expires_at,
            }
            finding.detail = detail
            applied.append(
                {
                    "waiver_id": waiver.id,
                    "rule_id": finding.rule_id,
                    "path": finding.path,
                    "expires_at": waiver.expires_at,
                }
            )
            break
    metadata = {"applied": applied, "active_count": len(active)}
    report.metadata["waivers"] = metadata
    return metadata


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


def _suggested_fix_for_rule(rule_id: str, remediation: str) -> str:
    examples = {
        "TG001": "Set `ephemeral = true` on sensitive variables where supported.",
        "TG002": (
            "Replace the literal secret with a variable, CI secret, "
            "or secret-manager reference."
        ),
        "TG006": "Set bucket ACLs to private and remove public-read/public-read-write grants.",
        "TG007": "Enable all S3 public access block flags on the bucket or account boundary.",
        "TG008": (
            "Replace `0.0.0.0/0` ingress with approved CIDR ranges "
            "or security group references."
        ),
        "TG009": (
            "Replace wildcard IAM actions/resources with the minimum actions "
            "and ARNs required."
        ),
        "TG010": "Move the instance to a private subnet or set public IP association to false.",
        "TG011": "Add an `aws_s3_bucket_server_side_encryption_configuration` resource.",
        "TG012": "Set `storage_encrypted = true` and configure a managed KMS key.",
        "TG013": "Use an HTTPS listener and attach an ACM or managed TLS certificate.",
        "TG015": "Set `publicly_accessible = false` on database resources.",
        "TG016": "Add required ownership, environment, and cost-center tags.",
        "TG019": "Disable public network access and route access through private endpoints.",
        "TG020": "Set `encrypted = true` and configure a KMS key for EBS volumes.",
        "TG021": "Remove public exposure or document an approved ingress exception.",
        "TG022": (
            "Enable encryption using the cloud provider's managed storage "
            "encryption controls."
        ),
        "TG023": "Add consistent ownership tags or labels to every managed resource.",
    }
    return examples.get(rule_id, remediation)


def _remediation_patch_preview(rule_id: str, finding: dict[str, Any]) -> str:
    path = str(finding.get("path") or "")
    examples = {
        "TG001": (
            'variable "example_secret" {\n'
            "  type      = string\n"
            "  sensitive = true\n"
            "  ephemeral = true\n"
            "}"
        ),
        "TG006": (
            'resource "aws_s3_bucket_acl" "example" {\n'
            "  bucket = aws_s3_bucket.example.id\n"
            '  acl    = "private"\n'
            "}"
        ),
        "TG007": (
            'resource "aws_s3_bucket_public_access_block" "example" {\n'
            "  bucket                  = aws_s3_bucket.example.id\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        ),
        "TG011": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "example" {\n'
            "  bucket = aws_s3_bucket.example.id\n\n"
            "  rule {\n"
            "    apply_server_side_encryption_by_default {\n"
            '      sse_algorithm = "AES256"\n'
            "    }\n"
            "  }\n"
            "}"
        ),
        "TG012": 'resource "aws_db_instance" "example" {\n  storage_encrypted = true\n}',
        "TG015": 'resource "aws_db_instance" "example" {\n  publicly_accessible = false\n}',
        "TG016": (
            "tags = {\n"
            '  Owner       = "platform-team"\n'
            '  Environment = "prod"\n'
            '  CostCenter  = "shared"\n'
            "}"
        ),
        "TG020": 'resource "aws_ebs_volume" "example" {\n  encrypted = true\n}',
        "TG023": (
            "labels = {\n"
            '  owner       = "platform-team"\n'
            '  environment = "prod"\n'
            "}"
        ),
    }
    preview = examples.get(rule_id, "")
    if preview and path:
        return f"# Review target: {path}\n{preview}"
    return preview


def _remediation_confidence(
    rule_id: str,
    patch_preview: str,
) -> Literal["low", "medium", "high"]:
    if not patch_preview:
        return "low"
    if rule_id in {"TG007", "TG011", "TG012", "TG015", "TG016", "TG020", "TG023"}:
        return "high"
    return "medium"


def _count_by(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _governance_risk_signals(
    decisions: dict[str, int],
    total_findings: int,
    active_waivers: list[PolicyWaiver],
    exports: list[EvidenceExport],
) -> list[str]:
    signals = []
    if decisions.get("block", 0):
        signals.append(f"{decisions['block']} blocked evaluations need remediation.")
    if active_waivers:
        signals.append(f"{len(active_waivers)} approved waivers are currently active.")
    if total_findings and not exports:
        signals.append("Findings exist without exported evidence records.")
    if not signals:
        signals.append("No immediate governance health risks detected.")
    return signals


def _metadata_severity(rule_id: str) -> Literal["low", "medium", "high"] | None:
    risk = str(RULE_METADATA.get(rule_id, {}).get("risk") or "")
    if risk in {"low", "medium", "high"}:
        return risk  # type: ignore[return-value]
    return None


def _waiver_is_active(waiver: PolicyWaiver) -> bool:
    try:
        expires = datetime.fromisoformat(waiver.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return expires > datetime.now(timezone.utc)


def _waiver_matches_finding(
    waiver: PolicyWaiver,
    finding: dict[str, Any],
    context: EvaluationContext,
) -> bool:
    if waiver.rule_id != finding.get("rule_id"):
        return False
    if waiver.path and waiver.path != finding.get("path"):
        return False
    detail = finding.get("detail") or {}
    if waiver.policy_id and waiver.policy_id != detail.get("policy_id"):
        return False
    if waiver.target_type and waiver.target:
        context_target = getattr(context, waiver.target_type, None)
        if context_target != waiver.target:
            return False
    return True


def _finding_is_waived(finding: Any) -> bool:
    if isinstance(finding, dict):
        return bool(finding.get("waiver_id") or (finding.get("detail") or {}).get("waiver"))
    return bool(
        getattr(finding, "waiver_id", None)
        or ((getattr(finding, "detail", None) or {}).get("waiver"))
    )


def _md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _sarif_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_location(path: str) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": 1},
        }
    }


def _explain_finding(
    finding: dict[str, Any],
    policies_by_id: dict[str, EnterprisePolicy],
    baseline_ids: list[str],
    adjustment_by_rule_path: dict[tuple[Any, Any], dict[str, Any]],
) -> FindingExplanation:
    detail = finding.get("detail") or {}
    policy_id = detail.get("policy_id")
    policy = policies_by_id.get(policy_id) if isinstance(policy_id, str) else None
    adjustment = adjustment_by_rule_path.get((finding.get("rule_id"), finding.get("path")))
    severity = finding.get("severity") if finding.get("severity") in SEVERITY_ORDER else "low"
    reason_parts = [f"{finding.get('rule_id')} reported {severity} severity"]
    if policy:
        reason_parts.append(f"matched policy {policy.name}")
    if adjustment:
        reason_parts.append(
            f"context raised severity from {adjustment.get('from')} to {adjustment.get('to')}"
        )
    waiver = detail.get("waiver")
    if waiver:
        reason_parts.append(f"approved waiver {waiver.get('id')} applies")
    if finding.get("suggested_fix"):
        reason_parts.append("a suggested fix is available")
    return FindingExplanation(
        rule_id=str(finding.get("rule_id")),
        severity=severity,
        message=str(finding.get("message")),
        path=finding.get("path"),
        policy_id=policy.id if policy else policy_id,
        policy_name=policy.name if policy else None,
        policy_status=policy.status if policy else detail.get("policy_status"),
        baseline_ids=baseline_ids,
        context_adjustment=adjustment,
        waiver_id=finding.get("waiver_id"),
        waiver_expires_at=finding.get("waiver_expires_at"),
        remediation=finding.get("remediation"),
        suggested_fix=finding.get("suggested_fix"),
        reason="; ".join(reason_parts) + ".",
    )


def _policy_explain_payload(policy: EnterprisePolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "rule_id": policy.rule_id,
        "name": policy.name,
        "severity": policy.severity,
        "status": policy.status,
        "owner": policy.metadata.owner,
        "standard": policy.metadata.standard,
        "control_id": policy.metadata.control_id,
    }


def _decision_reasons(
    result: EvaluationResult,
    explanations: list[FindingExplanation],
) -> list[str]:
    summary = result.report.get("summary", {})
    reasons: list[str] = []
    if result.decision == "pass":
        reasons.append("No blocking or warning findings were present after policy resolution.")
        if any(item.waiver_id for item in explanations):
            reasons.append("Approved waivers suppressed one or more otherwise actionable findings.")
    if result.decision == "warn":
        reasons.append("Medium-severity findings were present but no blocking threshold was met.")
    if result.decision == "block":
        if summary.get("high", 0) > 0:
            reasons.append("High-severity findings require blocking before apply.")
        if any(item.context_adjustment for item in explanations):
            reasons.append("Context-aware evaluation raised one or more finding severities.")
        if not reasons:
            reasons.append("The resolved enterprise policy set required a blocking decision.")
    if result.resolved_policy_ids:
        reasons.append(
            f"{len(result.resolved_policy_ids)} enterprise policies were resolved for this context."
        )
    return reasons


def _next_actions(
    result: EvaluationResult,
    explanations: list[FindingExplanation],
) -> list[str]:
    actions = []
    for explanation in explanations:
        if explanation.waiver_id:
            continue
        if explanation.suggested_fix:
            actions.append(f"{explanation.rule_id}: {explanation.suggested_fix}")
    if not actions and result.decision == "pass":
        actions.append("No action required. Keep the evaluation result as deployment evidence.")
    if result.decision in {"warn", "block"}:
        actions.append(
            "Re-run evaluation after applying fixes and keep the new result as evidence."
        )
    return list(dict.fromkeys(actions))


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
        if any(not _finding_is_waived(finding) for finding in report.findings):
            return "block"
    if any(
        finding.severity == "medium" and not _finding_is_waived(finding)
        for finding in report.findings
    ):
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
    return any(
        SEVERITY_ORDER[finding.severity] >= threshold
        for finding in report.findings
        if not _finding_is_waived(finding)
    )


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
