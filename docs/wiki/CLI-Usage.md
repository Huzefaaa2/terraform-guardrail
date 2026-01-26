# CLI Usage

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Install from PyPI

```bash
pip install terraform-guardrail
```

PyPI: https://pypi.org/project/terraform-guardrail/ (latest: 1.0.4)

## Scan

```bash
terraform-guardrail scan ./examples
terraform-guardrail scan ./examples --state ./examples/sample.tfstate
terraform-guardrail scan ./examples --schema
terraform-guardrail scan ./examples --policy-bundle baseline
terraform-guardrail scan ./examples --policy-bundle-path ./policies/baseline.tar.gz
terraform-guardrail scan ./examples --fail-on medium
```

## Generate snippets

```bash
terraform-guardrail generate aws aws_s3_bucket --name demo
terraform-guardrail generate azure azurerm_storage_account --name demo
```

## Policy registry (OPA bundles)

```bash
terraform-guardrail policy list
terraform-guardrail policy fetch baseline --destination ./policies
terraform-guardrail policy fetch baseline-signed --destination ./policies
terraform-guardrail policy init --destination ./my-bundle --bundle-name guardrail
```

Policy bundle evaluation requires the `opa` CLI on your PATH.

## Registry API

```bash
terraform-guardrail registry-api --host 0.0.0.0 --port 8090
```
