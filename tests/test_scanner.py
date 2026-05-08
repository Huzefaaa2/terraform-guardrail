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
