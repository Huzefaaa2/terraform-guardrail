# GitLab CI Templates

Terraform Guardrail MCP (TerraGuard) ships with a GitLab CI template you can include in any
project to run pre-apply guardrail scans.

## Include the template

```yaml
include:
  - project: "Huzefaaa2/terraform-guardrail"
    ref: "v1.0.4"
    file: "/.gitlab/terraform-guardrail.yml"
```

## Configure variables

```yaml
variables:
  TERRAFORM_GUARDRAIL_SCAN_PATH: "infra"
  TERRAFORM_GUARDRAIL_FAIL_ON: "high"
  TERRAFORM_GUARDRAIL_FORMAT: "pretty"
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
- `TERRAFORM_GUARDRAIL_POLICY_REGISTRY`: Registry base URL.
- `TERRAFORM_GUARDRAIL_POLICY_QUERY`: OPA query override.
