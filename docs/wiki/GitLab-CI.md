# GitLab CI Templates

Terraform Guardrail Multi-Cloud Policy (MCP) (TerraGuard) ships with a GitLab CI template you can include in any
project to run pre-apply guardrail scans.

## Include the template

```yaml
include:
  - project: "Huzefaaa2/terraform-guardrail"
    ref: "v1.0.5"
    file: "/.gitlab/terraform-guardrail.yml"
```

## Configure variables

```yaml
variables:
  TERRAFORM_GUARDRAIL_SCAN_PATH: "infra"
  TERRAFORM_GUARDRAIL_FAIL_ON: "high"
  TERRAFORM_GUARDRAIL_FORMAT: "pretty"
  TERRAFORM_GUARDRAIL_JSON_REPORT: "guardrail-report.json"
  TERRAFORM_GUARDRAIL_WRITE_REPORT: "true"
  TERRAFORM_GUARDRAIL_SARIF_REPORT: "guardrail-report.sarif"
  TERRAFORM_GUARDRAIL_JUNIT_REPORT: "guardrail-report.junit.xml"
  TERRAFORM_GUARDRAIL_WRITE_SARIF: "true"
  TERRAFORM_GUARDRAIL_WRITE_JUNIT: "true"
  # Optional local bundle path
  TERRAFORM_GUARDRAIL_POLICY_BUNDLE_PATH: "./policies/my-bundle.tar.gz"
```

## Policy bundle evaluation (optional)

```yaml
guardrail_scan:
  before_script:
    - python -m http.server 8081 --directory ops/policy-registry &
  variables:
    TERRAFORM_GUARDRAIL_POLICY_BUNDLE: "baseline-signed"
    TERRAFORM_GUARDRAIL_POLICY_REGISTRY: "http://localhost:8081"
```

## Variables reference

- `TERRAFORM_GUARDRAIL_SCAN_PATH`: Path to scan (default `.`).
- `TERRAFORM_GUARDRAIL_FORMAT`: `pretty` or `json`.
- `TERRAFORM_GUARDRAIL_FAIL_ON`: `low`, `medium`, or `high`.
- `TERRAFORM_GUARDRAIL_SCHEMA`: `true` to enable schema validation.
- `TERRAFORM_GUARDRAIL_STATE`: Optional `.tfstate` path.
- `TERRAFORM_GUARDRAIL_POLICY_BUNDLE`: Bundle ID to evaluate.
- `TERRAFORM_GUARDRAIL_POLICY_BUNDLE_PATH`: Local bundle path (`.tar.gz` or directory).
- `TERRAFORM_GUARDRAIL_POLICY_REGISTRY`: Registry base URL.
- `TERRAFORM_GUARDRAIL_POLICY_QUERY`: OPA query override.
- `TERRAFORM_GUARDRAIL_JSON_REPORT`: JSON artifact filename.
- `TERRAFORM_GUARDRAIL_WRITE_REPORT`: `true` to write the JSON report.
- `TERRAFORM_GUARDRAIL_SARIF_REPORT`: SARIF artifact filename.
- `TERRAFORM_GUARDRAIL_JUNIT_REPORT`: JUnit artifact filename.
- `TERRAFORM_GUARDRAIL_WRITE_SARIF`: `true` to write the SARIF report.
- `TERRAFORM_GUARDRAIL_WRITE_JUNIT`: `true` to write the JUnit report.
