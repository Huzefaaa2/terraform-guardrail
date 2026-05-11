# GitHub Actions Example (Terraform Guardrail)

This example simulates a GitHub Actions workflow that scans **good** and **bad** Terraform inputs
and generates JSON, SARIF, and JUnit outputs.

## Fixtures

- Good Terraform config: `../fixtures/terraform/good/`
- Bad Terraform config: `../fixtures/terraform/bad/`
- State file: `../fixtures/state/bad.tfstate`

## Workflow example

See `guardrail-example.yml` in this folder. Copy it into
`.github/workflows/guardrail-example.yml` to run in your repo.

## v3 service API example

See `guardrails-service-v3.yml` for a Guardrails-as-a-Service reference implementation. It starts
the TerraGuard API in the workflow, calls `POST /service/evaluate` with `policy_pack=aws-control-tower`,
and uploads the service response plus generated evidence.

## Outputs

Sample outputs are provided in `outputs/`:

- `guardrail-report.json`
- `guardrail-report.sarif`
- `guardrail-report.junit.xml`
- `guardrail-report.csv`
