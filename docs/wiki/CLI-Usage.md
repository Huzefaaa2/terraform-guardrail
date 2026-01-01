# CLI Usage

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Scan

```bash
terraform-guardrail scan ./examples
terraform-guardrail scan ./examples --state ./examples/sample.tfstate
terraform-guardrail scan ./examples --schema
```

## Generate snippets

```bash
terraform-guardrail generate aws aws_s3_bucket --name demo
terraform-guardrail generate azure azurerm_storage_account --name demo
```
