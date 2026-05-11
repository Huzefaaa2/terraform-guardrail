from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from terraform_guardrail.api.app import create_app
from terraform_guardrail.cli.app import app


def test_enterprise_api_evaluate_and_export(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
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

    client = TestClient(create_app())
    policy_response = client.post(
        "/policies",
        json={"name": "Sensitive variables", "rule_id": "TG001"},
    )
    assert policy_response.status_code == 200
    policy_id = policy_response.json()["id"]
    approve_response = client.post(
        f"/policies/{policy_id}/approve",
        json={"actor": "security"},
    )
    assert approve_response.status_code == 200
    baseline_response = client.post(
        "/baselines",
        json={"name": "org-baseline", "policy_ids": [policy_id], "approved": True},
    )
    assert baseline_response.status_code == 200

    eval_response = client.post(
        "/evaluate",
        json={"path": str(infra), "baseline": "org-baseline", "fail_on": "medium"},
    )
    assert eval_response.status_code == 200
    payload = eval_response.json()
    assert payload["decision"] == "block"
    assert payload["resolved_policy_ids"] == [policy_id]

    export_response = client.post(
        "/exports",
        json={"result_id": payload["id"], "format": "pdf"},
    )
    assert export_response.status_code == 200
    assert export_response.json()["format"] == "pdf"
    assert Path(export_response.json()["path"]).exists()

    drift_response = client.post("/drift/check", json={"path": str(infra), "snapshot_id": "prod"})
    assert drift_response.status_code == 200
    assert drift_response.json()["status"] == "baseline_created"

    gate_response = client.post(
        "/drift/gate",
        json={
            "path": str(infra),
            "snapshot_id": "prod-gate",
            "evidence_format": "json",
        },
    )
    assert gate_response.status_code == 200
    assert gate_response.json()["drift"]["status"] == "baseline_created"
    assert gate_response.json()["evidence"]["format"] == "json"


def test_enterprise_api_binding_endpoints(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())
    policy = client.post("/policies", json={"name": "Group policy", "rule_id": "TG011"}).json()

    response = client.post(
        "/bindings",
        json={
            "target_type": "group",
            "target": "platform",
            "policy_ids": [policy["id"]],
        },
    )
    assert response.status_code == 200
    assert response.json()["target"] == "platform"

    list_response = client.get("/bindings?target_type=group&target=platform")
    assert list_response.status_code == 200
    assert list_response.json()["bindings"][0]["policy_ids"] == [policy["id"]]

    group_response = client.get("/integrations/gitlab/groups/platform/policies")
    assert group_response.status_code == 200
    assert group_response.json()["policies"][0]["id"] == policy["id"]

    resolve_response = client.post("/bindings/resolve", json={"group": "platform"})
    assert resolve_response.status_code == 200
    assert resolve_response.json()["policy_ids"] == [policy["id"]]
    assert resolve_response.json()["binding_targets"] == ["group:platform"]


def test_enterprise_api_policy_packs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())

    list_response = client.get("/packs")
    assert list_response.status_code == 200
    assert "pci-dss" in {pack["id"] for pack in list_response.json()["packs"]}

    show_response = client.get("/packs/aws-control-tower")
    assert show_response.status_code == 200
    assert show_response.json()["baseline_name"] == "aws-control-tower-baseline"

    install_response = client.post(
        "/packs/aws-control-tower/install",
        json={"actor": "platform"},
    )
    assert install_response.status_code == 200
    payload = install_response.json()
    assert payload["pack_id"] == "aws-control-tower"
    assert payload["baseline_id"]

    baseline_response = client.get("/baselines")
    assert baseline_response.status_code == 200
    assert baseline_response.json()["baselines"][0]["name"] == "aws-control-tower-baseline"


def test_guardrails_as_a_service_evaluate_contract(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    client = TestClient(create_app())

    response = client.post(
        "/service/evaluate",
        json={
            "path": str(infra),
            "request_id": "ci-123",
            "provider": "aws",
            "policy_pack": "aws-control-tower",
            "fail_on": "high",
            "evidence_format": "json",
            "actor": "github-actions",
            "context": {"repo": "payments-infra", "environment": "prod"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "ci-123"
    assert payload["status"] == "completed"
    assert payload["decision"] == "block"
    assert payload["links"]["result"] == f"/results/{payload['result_id']}"
    assert payload["links"]["evidence"] == f"/exports/{payload['evidence']['id']}"
    assert payload["resolved"]["policy_pack"] == "aws-control-tower"
    assert payload["resolved"]["policy_pack_install_id"]
    assert payload["resolved"]["policy_ids"]
    assert payload["result"]["request_id"] == "ci-123"
    assert payload["result"]["service_metadata"]["service_endpoint"] == "/service/evaluate"
    assert Path(payload["evidence"]["path"]).exists()

    stored = client.get(payload["links"]["result"])
    assert stored.status_code == 200
    assert stored.json()["request_id"] == "ci-123"


def test_enterprise_api_baseline_lifecycle(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    client = TestClient(create_app())
    policy = client.post("/policies", json={"name": "Baseline policy", "rule_id": "TG011"}).json()
    baseline = client.post(
        "/baselines",
        json={"name": "org-baseline", "policy_ids": [policy["id"]]},
    ).json()

    version_response = client.post(
        f"/baselines/{baseline['id']}/versions",
        json={"version": "1.0.0", "policy_ids": [policy["id"]], "actor": "alice"},
    )
    assert version_response.status_code == 200
    assert version_response.json()["version"] == "1.0.0"

    approve_response = client.post(
        f"/baselines/{baseline['id']}/approve",
        json={"actor": "bob", "comment": "approved"},
    )
    assert approve_response.status_code == 200
    assert approve_response.json()["version"] == "1.0.0"

    history_response = client.get(f"/baselines/{baseline['id']}/approvals")
    assert history_response.status_code == 200
    assert history_response.json()["approvals"][0]["actor"] == "bob"


def test_enterprise_api_policy_preview(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    client = TestClient(create_app())
    policy = client.post("/policies", json={"name": "Bucket encryption", "rule_id": "TG011"}).json()

    response = client.post(
        f"/policies/{policy['id']}/preview",
        json={"path": str(infra), "actor": "security"},
    )

    assert response.status_code == 200
    assert response.json()["summary"]["findings"] == 1
    assert response.json()["findings"][0]["rule_id"] == "TG011"


def test_enterprise_cli_evaluate_and_fail_on(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
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

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["evaluate", str(infra), "--fail-on", "medium", "--format", "json"],
    )

    assert result.exit_code == 1
    assert '"decision": "block"' in result.stdout


def test_enterprise_cli_policy_and_baseline(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    runner = CliRunner()

    create = runner.invoke(
        app,
        [
            "enterprise",
            "policy",
            "create",
            "--name",
            "Sensitive variables",
            "--rule-id",
            "TG001",
            "--owner",
            "security",
            "--format",
            "json",
        ],
    )
    assert create.exit_code == 0
    assert "Sensitive variables" in create.stdout

    policies = runner.invoke(app, ["enterprise", "policy", "list"])
    assert policies.exit_code == 0
    assert "Sensitive variables" in policies.stdout

    baseline = runner.invoke(
        app,
        ["enterprise", "baseline", "create", "--name", "org-baseline", "--approved"],
    )
    assert baseline.exit_code == 0
    assert "org-baseline" in baseline.stdout

    version = runner.invoke(
        app,
        [
            "enterprise",
            "baseline",
            "version",
            "org-baseline",
            "--version",
            "1.0.0",
        ],
    )
    assert version.exit_code == 0
    assert "1.0.0" in version.stdout

    approval = runner.invoke(
        app,
        ["enterprise", "baseline", "approve", "org-baseline", "--actor", "security"],
    )
    assert approval.exit_code == 0
    assert "security" in approval.stdout

    history = runner.invoke(app, ["enterprise", "baseline", "history", "org-baseline"])
    assert history.exit_code == 0
    assert "approval approved 1.0.0 by security" in history.stdout


def test_enterprise_cli_binding_create_and_list(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    runner = CliRunner()

    create = runner.invoke(
        app,
        [
            "enterprise",
            "binding",
            "create",
            "--target-type",
            "group",
            "--target",
            "platform",
            "--policy-id",
            "pol_example",
            "--parent",
            "acme",
        ],
    )
    assert create.exit_code == 0
    assert "platform" in create.stdout

    bindings = runner.invoke(app, ["enterprise", "binding", "list", "--target", "platform"])
    assert bindings.exit_code == 0
    assert "group:platform" in bindings.stdout

    resolved = runner.invoke(app, ["enterprise", "binding", "resolve", "--group", "platform"])
    assert resolved.exit_code == 0
    assert "Target: group:platform" in resolved.stdout
    assert "pol_example" in resolved.stdout


def test_enterprise_cli_policy_pack_install(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    runner = CliRunner()

    list_result = runner.invoke(app, ["enterprise", "pack", "list"])
    assert list_result.exit_code == 0
    assert "pci-dss" in list_result.stdout

    show_result = runner.invoke(app, ["enterprise", "pack", "show", "pci-dss"])
    assert show_result.exit_code == 0
    assert "PCI DSS Cloud Controls" in show_result.stdout

    install_result = runner.invoke(
        app,
        ["enterprise", "pack", "install", "pci-dss", "--actor", "platform", "--format", "json"],
    )
    assert install_result.exit_code == 0
    assert '"pack_id": "pci-dss"' in install_result.stdout

    baseline_result = runner.invoke(app, ["enterprise", "baseline", "list"])
    assert baseline_result.exit_code == 0
    assert "pci-dss-baseline" in baseline_result.stdout


def test_enterprise_cli_evidence_pdf_export(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    evaluate = runner.invoke(app, ["evaluate", str(infra), "--format", "json"])
    assert evaluate.exit_code == 0
    result_id = evaluate.stdout.split('"id": "')[1].split('"')[0]

    export = runner.invoke(app, ["evidence", "export", result_id, "--format", "pdf"])

    assert export.exit_code == 0
    exported_path = export.stdout.strip().split("Evidence exported: ")[1].replace("\n", "")
    assert Path(exported_path).read_bytes().startswith(b"%PDF-1.4")


def test_enterprise_cli_drift_gate_blocks_on_change(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GUARDRAIL_ENTERPRISE_DATA_DIR", str(tmp_path / "store"))
    infra = tmp_path / "main.tf"
    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    created = runner.invoke(
        app,
        [
            "enterprise",
            "drift-gate",
            str(infra),
            "--snapshot-id",
            "prod",
            "--evidence-format",
            "json",
            "--format",
            "json",
        ],
    )
    assert created.exit_code == 0
    assert '"status": "baseline_created"' in created.stdout

    infra.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}
""",
        encoding="utf-8",
    )
    changed = runner.invoke(
        app,
        ["enterprise", "drift-gate", str(infra), "--snapshot-id", "prod", "--format", "json"],
    )
    assert changed.exit_code == 1
    assert '"decision": "block"' in changed.stdout
    assert "drift_changed" in changed.stdout
