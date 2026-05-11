# GitLab CI Example (Terraform Guardrail)

This example simulates a GitLab CI pipeline using the shared template and shows how to scan
**good** and **bad** Terraform inputs, including `.tf`, `.tfvars`, `.hcl`, and `.tfstate` files.

## Fixtures

- Good Terraform config: `../fixtures/terraform/good/`
- Bad Terraform config: `../fixtures/terraform/bad/`
- State file: `../fixtures/state/bad.tfstate`

## Pipeline example

See `.gitlab-ci.yml` in this folder. It uses the published template and points to the fixtures.

## v3 service API example

See `service-v3.gitlab-ci.yml` for a Guardrails-as-a-Service reference implementation. It starts
the TerraGuard API in the job, calls `POST /service/evaluate` with `policy_pack=aws-control-tower`,
and stores the service response plus generated evidence as artifacts.

## Outputs

Sample outputs are provided in `outputs/`:

- `guardrail-report.json`
- `guardrail-report.sarif`
- `guardrail-report.junit.xml`
- `guardrail-report.csv`

## Local simulation

```bash
terraform-guardrail scan ../fixtures/terraform/good

terraform-guardrail scan ../fixtures/terraform/bad \
  --state ../fixtures/state/bad.tfstate \
  --schema \
  --format json > outputs/guardrail-report.json
```

Use the JSON output to generate SARIF/JUnit if desired.
