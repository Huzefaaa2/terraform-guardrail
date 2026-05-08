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
    check_drift,
    evaluate_enterprise,
    export_evidence,
    preview_policy,
    resolve_policy_ids,
    resolve_policy_set,
    run_drift_gate,
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
