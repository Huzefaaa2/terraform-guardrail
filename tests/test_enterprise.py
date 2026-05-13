from __future__ import annotations

import json
from pathlib import Path

from terraform_guardrail.enterprise import (
    Baseline,
    EnterprisePolicy,
    EnterpriseStore,
    EvaluationContext,
    GroupPolicyBinding,
    PolicyMetadata,
    PolicyWaiver,
    RiskProfile,
    ScheduledScanTarget,
    check_drift,
    create_remediation_plan,
    ensure_policy_pack_installed,
    evaluate_enterprise,
    explain_evaluation,
    export_evidence,
    get_builtin_policy_pack,
    get_rule_recommendation,
    governance_health_report,
    install_policy_pack,
    list_builtin_policy_packs,
    list_rule_recommendations,
    preview_policy,
    render_evaluation_junit,
    render_evaluation_sarif,
    render_explanation_markdown,
    render_remediation_markdown,
    resolve_policy_ids,
    resolve_policy_set,
    run_drift_gate,
    run_scheduled_scan,
)


def test_enterprise_store_policy_lifecycle_and_audit(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)
    policy = store.save_policy(
        EnterprisePolicy(
            name="S3 encryption",
            rule_id="TG011",
            metadata=PolicyMetadata(owner="security", standard="SOC2", control_id="CC6.1"),
        ),
        actor="alice",
    )

    store.add_policy_version(policy.id, version="1.0.0", actor="alice")
    approval = store.approve_policy(policy.id, actor="bob", comment="approved")

    assert store.get_policy(policy.id).status == "approved"
    assert approval.version == "1.0.0"
    assert [event.action for event in store.audit_events()] == [
        "policy.create",
        "policy.update",
        "policy.version.create",
        "policy.update",
        "policy.approve",
    ]


def test_baseline_resolution_and_group_inheritance(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)
    org_policy = store.save_policy(EnterprisePolicy(name="Org", rule_id="TG008"))
    group_policy = store.save_policy(EnterprisePolicy(name="Group", rule_id="TG011"))
    baseline = store.save_baseline(
        Baseline(name="org-baseline", policy_ids=[org_policy.id], approved=True)
    )
    store.save_binding(
        GroupPolicyBinding(
            target_type="group",
            target="platform",
            policy_ids=[group_policy.id],
            baseline_ids=[baseline.id],
        )
    )

    resolved = resolve_policy_ids(
        store,
        context=EvaluationContext(
            baseline="org-baseline",
            group="platform",
        ),
    )

    assert resolved == [org_policy.id, group_policy.id]


def test_builtin_policy_pack_install_creates_policies_baseline_and_audit(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)

    packs = list_builtin_policy_packs()
    assert {pack.id for pack in packs} >= {"pci-dss", "aws-control-tower"}
    pack = get_builtin_policy_pack("pci-dss")
    result = install_policy_pack("pci-dss", store=store, actor="platform")

    assert result.pack_id == pack.id
    assert len(result.policy_ids) == len(pack.policies)
    assert result.baseline_id is not None
    baseline = store.get_baseline(result.baseline_id)
    assert baseline.name == "pci-dss-baseline"
    assert baseline.approved is True
    assert baseline.policy_ids == result.policy_ids
    policies = [store.get_policy(policy_id) for policy_id in result.policy_ids]
    assert {policy.status for policy in policies} == {"approved"}
    assert policies[0].metadata.standard == "PCI DSS"
    assert store.audit_events()[-1].action == "policy_pack.install"


def test_ensure_policy_pack_installed_reuses_existing_install(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)

    first = ensure_policy_pack_installed("aws-control-tower", store=store, actor="platform")
    second = ensure_policy_pack_installed("aws-control-tower", store=store, actor="platform")

    assert second.id == first.id
    assert len(store.list_policies()) == 3
    assert len(store.list_baselines()) == 1


def test_binding_parent_inheritance_resolves_repo_to_group_and_org(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)
    org_policy = store.save_policy(EnterprisePolicy(name="Org", rule_id="TG008"))
    group_policy = store.save_policy(EnterprisePolicy(name="Group", rule_id="TG011"))
    repo_policy = store.save_policy(EnterprisePolicy(name="Repo", rule_id="TG016"))
    store.save_binding(
        GroupPolicyBinding(target_type="org", target="acme", policy_ids=[org_policy.id])
    )
    store.save_binding(
        GroupPolicyBinding(
            target_type="group",
            target="platform",
            policy_ids=[group_policy.id],
            parent="acme",
        )
    )
    store.save_binding(
        GroupPolicyBinding(
            target_type="repo",
            target="infra",
            policy_ids=[repo_policy.id],
            parent="platform",
        )
    )

    resolved = resolve_policy_ids(store, EvaluationContext(repo="infra"))

    assert resolved == [org_policy.id, group_policy.id, repo_policy.id]

    policy_set = resolve_policy_set(store, EvaluationContext(repo="infra"))
    assert policy_set.target_type == "repo"
    assert policy_set.target == "infra"
    assert policy_set.binding_targets == ["group:platform", "org:acme", "repo:infra"]
    assert [policy["name"] for policy in policy_set.policies] == ["Org", "Group", "Repo"]


def test_baseline_version_and_approval_lifecycle(tmp_path: Path) -> None:
    store = EnterpriseStore(tmp_path)
    first = store.save_policy(EnterprisePolicy(name="First", rule_id="TG001"))
    second = store.save_policy(EnterprisePolicy(name="Second", rule_id="TG002"))
    baseline = store.save_baseline(Baseline(name="org-baseline", policy_ids=[first.id]))

    version = store.add_baseline_version(
        baseline.id,
        version="1.0.0",
        policy_ids=[first.id, second.id],
        actor="alice",
    )
    approval = store.approve_baseline(baseline.id, actor="bob", comment="ship it")

    updated = store.get_baseline(baseline.id)
    assert updated.version == "1.0.0"
    assert updated.policy_ids == [first.id, second.id]
    assert updated.approved is True
    assert version.policy_ids == [first.id, second.id]
    assert approval.version == "1.0.0"
    assert [item.action for item in store.audit_events()] == [
        "policy.create",
        "policy.create",
        "baseline.create",
        "baseline.update",
        "baseline.version.create",
        "baseline.update",
        "baseline.approve",
    ]


def test_evaluate_enriches_findings_and_exports_evidence(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    policy = store.save_policy(
        EnterprisePolicy(
            name="Encrypted buckets",
            rule_id="TG011",
            severity="block",
            metadata=PolicyMetadata(
                owner="platform-security",
                standard="SOC2",
                control_id="CC6.6",
                risk="high",
                remediation="Enable default SSE.",
            ),
        )
    )
    store.approve_policy(policy.id)
    store.save_baseline(Baseline(name="org-baseline", policy_ids=[policy.id], approved=True))

    result = evaluate_enterprise(infra, baseline="org-baseline", store=store)
    export_json = export_evidence(result.id, format="json", store=store)
    export_csv = export_evidence(result.id, format="csv", store=store)
    export_pdf = export_evidence(result.id, format="pdf", store=store)

    finding = result.report["findings"][0]
    assert result.decision == "block"
    assert finding["owner"] == "platform-security"
    assert finding["standard"] == "SOC2"
    assert Path(export_json.path).exists()
    assert Path(export_csv.path).read_text(encoding="utf-8").startswith("result_id,decision")
    assert Path(export_pdf.path).read_bytes().startswith(b"%PDF-1.4")


def test_evaluate_adds_default_rule_remediation_without_enterprise_policy(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    result = evaluate_enterprise(infra, store=EnterpriseStore(tmp_path / "store"))

    finding = result.report["findings"][0]
    assert finding["rule_id"] == "TG011"
    assert finding["risk"] == "medium"
    assert finding["remediation"] == "Enable S3 default encryption with KMS or AES256."
    assert finding["suggested_fix"] == (
        "Add an `aws_s3_bucket_server_side_encryption_configuration` resource."
    )


def test_remediation_plan_generates_actions_and_health_report(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    result = evaluate_enterprise(infra, store=store)

    plan = create_remediation_plan(result.id, store=store, actor="platform")
    markdown = render_remediation_markdown(plan)
    health = governance_health_report(store=store)

    assert plan.result_id == result.id
    assert plan.actions[0].rule_id == "TG011"
    assert plan.actions[0].patch_type == "terraform_snippet"
    assert "aws_s3_bucket_server_side_encryption_configuration" in plan.actions[0].patch_preview
    assert "Terraform Guardrail Remediation Plan" in markdown
    assert store.get_remediation_plan(plan.id).id == plan.id
    assert store.audit_events()[-1].action == "remediation.plan.create"
    assert health.totals["evaluations"] == 1
    assert health.totals["remediation_plans"] == 1
    assert health.decisions["warn"] == 1
    assert health.top_rules[0]["rule_id"] == "TG011"


def test_scheduled_scan_target_runs_and_updates_health(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    target = store.save_scheduled_scan_target(
        ScheduledScanTarget(
            name="daily-prod",
            path=str(infra),
            cadence="daily",
            provider="aws",
            context={"environment": "prod", "risk_tier": "high"},
        ),
        actor="platform",
    )

    run = run_scheduled_scan(target.id, store=store, actor="scheduler")
    health = governance_health_report(store=store)

    assert run.status == "completed"
    assert run.result_id is not None
    assert run.decision == "block"
    assert store.get_evaluation(run.result_id).service_metadata["scheduled_scan_target_id"] == (
        target.id
    )
    assert health.totals["scheduled_targets"] == 1
    assert health.totals["scheduled_runs"] == 1
    assert [event.action for event in store.audit_events()][-2:] == [
        "evaluation.create",
        "scheduled_scan.run",
    ]


def test_context_aware_evaluation_escalates_production_findings(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")

    result = evaluate_enterprise(
        infra,
        context={"environment": "prod", "risk_tier": "high", "repo": "payments"},
        store=store,
    )

    finding = result.report["findings"][0]
    intelligence = result.service_metadata["intelligence"]
    assert result.decision == "block"
    assert result.context.environment == "prod"
    assert result.context.risk_tier == "high"
    assert finding["rule_id"] == "TG011"
    assert finding["severity"] == "high"
    assert finding["detail"]["context_severity"]["from"] == "medium"
    assert intelligence["profile"]["id"] == "default-prod-high-risk"
    assert intelligence["adjustments"][0]["to"] == "high"
    assert intelligence["recommendations"][0]["suggested_fix"]


def test_explainability_report_describes_decision_context_and_actions(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    policy = store.save_policy(
        EnterprisePolicy(
            name="S3 encryption",
            rule_id="TG011",
            severity="block",
            metadata=PolicyMetadata(owner="security", standard="SOC2"),
        )
    )
    store.approve_policy(policy.id)
    store.save_baseline(Baseline(name="org-baseline", policy_ids=[policy.id], approved=True))

    result = evaluate_enterprise(
        infra,
        baseline="org-baseline",
        context={"environment": "prod", "risk_tier": "high"},
        store=store,
    )
    explanation = explain_evaluation(result.id, store=store)

    assert explanation.result_id == result.id
    assert explanation.decision == "block"
    assert explanation.risk_profile
    assert explanation.risk_profile["id"] == "default-prod-high-risk"
    assert explanation.baseline_ids
    assert explanation.applied_policy_ids == [policy.id]
    assert explanation.finding_explanations[0].policy_name == "S3 encryption"
    assert explanation.finding_explanations[0].context_adjustment
    assert explanation.next_actions[0].startswith("TG011:")
    assert any("High-severity" in reason for reason in explanation.reasons)
    markdown = render_explanation_markdown(explanation)
    assert markdown.startswith("## Terraform Guardrail Evaluation")
    assert "**Decision:** `BLOCK`" in markdown
    assert "TG011" in markdown
    assert "Next Actions" in markdown
    sarif = render_evaluation_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "TG011"
    junit = render_evaluation_junit(result)
    assert "<testsuite" in junit
    assert 'failures="' in junit
    assert "TG011" in junit


def test_custom_risk_profile_can_override_rule_severity(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.nano"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    profile = store.save_risk_profile(
        RiskProfile(
            name="regulated-dev",
            environments=["dev"],
            risk_tiers=["medium"],
            rule_severity_overrides={"TG014": "medium"},
            default_fail_on="medium",
        )
    )

    result = evaluate_enterprise(
        infra,
        context={"environment": "dev", "risk_tier": "medium", "risk_profile": profile.id},
        store=store,
    )

    finding = next(item for item in result.report["findings"] if item["rule_id"] == "TG014")
    assert finding["severity"] == "medium"
    assert result.decision == "block"
    assert result.service_metadata["intelligence"]["profile"]["id"] == profile.id


def test_approved_waiver_suppresses_matching_finding_for_decision(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
variable "db_password" {
  type      = string
  sensitive = true
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    waiver = store.save_waiver(
        PolicyWaiver(
            rule_id="TG001",
            reason="Legacy module migration",
            owner="platform",
            expires_at="2099-01-01T00:00:00Z",
            requested_by="alice",
        ),
        actor="alice",
    )
    store.approve_waiver(waiver.id, actor="security")

    result = evaluate_enterprise(infra, fail_on="medium", store=store)
    finding = result.report["findings"][0]
    explanation = explain_evaluation(result.id, store=store)

    assert result.decision == "pass"
    assert finding["waiver_id"] == waiver.id
    assert result.service_metadata["waivers"]["applied"][0]["waiver_id"] == waiver.id
    assert explanation.applied_waivers[0]["waiver_id"] == waiver.id
    assert explanation.finding_explanations[0].waiver_id == waiver.id
    assert any("waivers suppressed" in reason for reason in explanation.reasons)
    assert store.audit_events()[-1].action == "evaluation.create"


def test_rule_recommendations_are_available() -> None:
    recommendations = list_rule_recommendations()
    assert {item.rule_id for item in recommendations} >= {"TG001", "TG011", "TG023"}
    assert get_rule_recommendation("TG011").suggested_fix.startswith("Add an")


def test_policy_preview_filters_to_selected_policy_rule(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")
    policy = store.save_policy(
        EnterprisePolicy(
            name="Bucket encryption",
            rule_id="TG011",
            metadata=PolicyMetadata(owner="security"),
        )
    )

    preview = preview_policy(policy.id, infra, store=store)

    assert preview.policy_id == policy.id
    assert preview.summary["findings"] == 1
    assert preview.findings[0]["rule_id"] == "TG011"
    assert preview.findings[0]["owner"] == "security"
    assert store.audit_events()[-1].action == "policy.preview"


def test_drift_check_creates_matches_and_detects_change(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")

    created = check_drift(infra, snapshot_id="prod", store=store)
    matched = check_drift(infra, snapshot_id="prod", store=store)
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}
""",
        encoding="utf-8",
    )
    changed = check_drift(infra, snapshot_id="prod", store=store)

    assert created.status == "baseline_created"
    assert matched.status == "matched"
    assert changed.drifted is True
    assert changed.added


def test_drift_gate_creates_snapshot_and_blocks_on_change(tmp_path: Path) -> None:
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    store = EnterpriseStore(tmp_path / "store")

    created = run_drift_gate(
        infra,
        snapshot_id="prod",
        export_format="json",
        store=store,
    )
    assert created.decision == "warn"
    assert created.drift.status == "baseline_created"
    assert created.evidence is not None

    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}
""",
        encoding="utf-8",
    )
    changed = run_drift_gate(infra, snapshot_id="prod", store=store)

    assert changed.decision == "block"
    assert changed.drift.drifted is True
    assert "drift_changed" in changed.reasons


def test_aws_codebuild_example_contains_enterprise_gate() -> None:
    buildspec = Path("examples/aws-codepipeline/buildspec.yml").read_text(encoding="utf-8")
    assert "terraform-guardrail evaluate" in buildspec
    assert "terraform-guardrail evidence export" in buildspec
    assert "guardrail-report.json" in buildspec
    assert "guardrail-evidence.json" in buildspec

    sample = json.loads(
        Path("examples/aws-codepipeline/outputs/guardrail-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    assert sample["decision"] == "block"
