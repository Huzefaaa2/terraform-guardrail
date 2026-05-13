from __future__ import annotations

from fastapi.testclient import TestClient

from terraform_guardrail.enterprise import EnterprisePolicy, EnterpriseStore
from terraform_guardrail.web.app import _next_rule_id, create_app


def test_web_scan_accepts_multiple_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())

    response = client.post(
        "/scan",
        files=[
            (
                "tf_files",
                (
                    "main.tf",
                    b'variable "db_password" { type = string sensitive = true }',
                    "text/plain",
                ),
            ),
            (
                "tf_files",
                (
                    "modules/app/secrets.tfvars",
                    b'api_key = "secret"',
                    "text/plain",
                ),
            ),
        ],
    )

    assert response.status_code == 200
    assert "Intelligent evaluation" in response.text
    assert "TG001" in response.text
    assert "TG002" in response.text
    assert "Suggested fixes" in response.text
    assert "Production high-risk" in response.text


def test_web_policy_rule_id_is_allocated_without_conflicts(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    store = EnterpriseStore()
    assert _next_rule_id(store) == "TG024"

    store.save_policy(EnterprisePolicy(name="Existing", rule_id="TG024"))
    client = TestClient(create_app())
    response = client.post(
        "/policies",
        data={
            "name": "Next policy",
            "owner": "security",
            "standard": "SOC2",
            "control_id": "CC6.1",
            "description": "Autonumbered",
            "remediation": "Fix it",
        },
    )

    assert response.status_code == 200
    policies = EnterpriseStore().list_policies()
    assert {policy.rule_id for policy in policies} == {"TG024", "TG025"}
    assert "TG025" in response.text


def test_web_lists_default_rules_and_renders_rule_detail(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    EnterpriseStore().save_policy(EnterprisePolicy(name="Enterprise policy", rule_id="TG021"))
    client = TestClient(create_app())

    response = client.get("/?rule_id=TG008")

    assert response.status_code == 200
    assert "Default Rules" in response.text
    assert "Enterprise Policies" in response.text
    assert "TG001" in response.text
    assert "TG020" in response.text
    assert "TG021" in response.text
    assert "Security group ingress open to the world" in response.text
    assert "Default rule detail" in response.text
    assert "Risk Profiles" in response.text
    assert "Production high-risk" in response.text


def test_web_displays_how_to_guide_links(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "How to guides" in response.text
    assert "https://github.com/Huzefaaa2/terraform-guardrail/wiki/How-To-Guides" in response.text
    assert "How-To-Scan-a-Terraform-Workspace" in response.text
    assert "How-To-Create-an-Enterprise-Policy" in response.text


def test_web_creates_group_binding(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    policy = EnterpriseStore().save_policy(EnterprisePolicy(name="Group policy", rule_id="TG021"))
    client = TestClient(create_app())

    response = client.post(
        "/bindings",
        data={
            "target_type": "group",
            "target": "platform",
            "policy_id": policy.id,
            "baseline_id": "",
            "parent": "acme",
        },
    )

    assert response.status_code == 200
    assert "group:platform" in response.text
    binding = EnterpriseStore().list_bindings()[0]
    assert binding.policy_ids == [policy.id]
    assert binding.parent == "acme"

    resolved = client.post(
        "/bindings/resolve",
        data={"org": "", "group": "platform", "repo": "", "baseline": ""},
    )
    assert resolved.status_code == 200
    assert "Resolved enforcement" in resolved.text
    assert "Group policy" in resolved.text


def test_web_baseline_lifecycle(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    policy = EnterpriseStore().save_policy(
        EnterprisePolicy(name="Baseline policy", rule_id="TG021")
    )
    client = TestClient(create_app())

    created = client.post(
        "/baselines",
        data={
            "name": "org-baseline",
            "policy_id": policy.id,
            "scope": "org",
            "version": "0.1.0",
        },
    )
    assert created.status_code == 200
    baseline = EnterpriseStore().list_baselines()[0]
    assert "org-baseline" in created.text

    versioned = client.post(
        f"/baselines/{baseline.id}/version",
        data={"version": "1.0.0", "policy_id": policy.id},
    )
    assert versioned.status_code == 200
    approved = client.post(f"/baselines/{baseline.id}/approve")
    assert approved.status_code == 200
    assert EnterpriseStore().get_baseline(baseline.id).approved is True


def test_web_policy_preview(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    policy = EnterpriseStore().save_policy(
        EnterprisePolicy(name="Bucket encryption", rule_id="TG011")
    )
    client = TestClient(create_app())

    response = client.post(
        f"/policies/{policy.id}/preview",
        files=[
            (
                "preview_files",
                (
                    "main.tf",
                    b'resource "aws_s3_bucket" "logs" { bucket = "logs" }',
                    "text/plain",
                ),
            )
        ],
    )

    assert response.status_code == 200
    assert "Policy preview" in response.text
    assert "Bucket encryption" in response.text
    assert "TG011" in response.text


def test_web_waiver_lifecycle_and_scan_annotation(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())

    created = client.post(
        "/waivers",
        data={
            "rule_id": "TG001",
            "reason": "Migration window",
            "owner": "platform",
            "expires_at": "2099-01-01T00:00:00Z",
            "path": "",
            "approve": "true",
        },
    )
    assert created.status_code == 200
    waiver = EnterpriseStore().list_waivers()[0]
    assert waiver.status == "approved"
    assert "Policy waivers" in created.text
    assert "Migration window" in created.text

    response = client.post(
        "/scan",
        data={"fail_on": "medium"},
        files=[
            (
                "tf_files",
                (
                    "main.tf",
                    b'variable "db_password" { type = string sensitive = true }',
                    "text/plain",
                ),
            )
        ],
    )
    assert response.status_code == 200
    assert "decision-pass" in response.text
    assert f"Waived by {waiver.id}" in response.text

    revoked = client.post(f"/waivers/{waiver.id}/revoke")
    assert revoked.status_code == 200
    assert EnterpriseStore().get_waiver(waiver.id).status == "revoked"
