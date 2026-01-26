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

## Outputs

Sample outputs are provided in `outputs/`:

- `guardrail-report.json`
- `guardrail-report.sarif`
- `guardrail-report.junit.xml`
- `guardrail-report.csv`
