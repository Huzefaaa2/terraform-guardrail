from pathlib import Path

from terraform_guardrail.scanner.scan import scan_path


def test_scan_detects_sensitive_variable(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable \"db_password\" {
  type = string
  sensitive = true
}
""",
        encoding="utf-8",
    )

    report = scan_path(tf_file)
    rule_ids = {finding.rule_id for finding in report.findings}
    assert "TG001" in rule_ids


def test_scan_normalizes_hcl_parser_quoted_labels_and_values(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}
""",
        encoding="utf-8",
    )

    report = scan_path(tf_file)
    rule_ids = {finding.rule_id for finding in report.findings}
    assert {"TG006", "TG011"}.issubset(rule_ids)


def test_scan_emits_cross_provider_invariants_for_aws_azure_and_gcp(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}

resource "azurerm_storage_account" "logs" {
  name                          = "logs"
  resource_group_name           = "rg"
  location                      = "eastus"
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = true
}

resource "google_storage_bucket" "logs" {
  name          = "logs"
  location      = "US"
  predefined_acl = "publicRead"
}
""",
        encoding="utf-8",
    )

    report = scan_path(tf_file)

    invariant_findings = [finding for finding in report.findings if finding.rule_id == "TG021"]
    assert {finding.detail["provider"] for finding in invariant_findings} == {
        "aws",
        "azure",
        "gcp",
    }
    assert {finding.detail["invariant"] for finding in invariant_findings} == {
        "public_exposure"
    }


def test_scan_emits_cross_provider_encryption_and_ownership_invariants(
    tmp_path: Path,
) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
}

resource "google_compute_disk" "data" {
  name = "data"
  type = "pd-standard"
  zone = "us-central1-a"
  labels = {
    owner = "platform"
  }
}
""",
        encoding="utf-8",
    )

    report = scan_path(tf_file)
    rule_ids = {finding.rule_id for finding in report.findings}

    assert "TG022" in rule_ids
    assert "TG023" in rule_ids
    gcp_ownership = [
        finding
        for finding in report.findings
        if finding.rule_id == "TG023" and finding.detail["provider"] == "gcp"
    ]
    assert gcp_ownership[0].detail["required"] == ["owner", "environment"]
