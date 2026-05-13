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

PyPI: https://pypi.org/project/terraform-guardrail/ (latest: 4.0.0)

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
terraform-guardrail policy validate ./my-bundle.tar.gz
```

Policy bundle evaluation requires the `opa` CLI on your PATH.

## Registry API

```bash
terraform-guardrail registry-api --host 0.0.0.0 --port 8090
```

## Enterprise context intelligence

```bash
terraform-guardrail evaluate ./infra \
  --context environment=prod \
  --context risk_tier=high \
  --format json
```

```bash
terraform-guardrail enterprise risk-profile list
terraform-guardrail enterprise risk-profile show default-prod-high-risk
terraform-guardrail enterprise risk-profile create \
  --name regulated-prod \
  --environment prod \
  --risk-tier critical \
  --severity-override TG011=high \
  --default-fail-on medium
```

```bash
terraform-guardrail enterprise recommendations
terraform-guardrail enterprise recommendations --rule-id TG011
terraform-guardrail enterprise explain <evaluation-result-id>
terraform-guardrail enterprise explain <evaluation-result-id> --format json
terraform-guardrail enterprise explain <evaluation-result-id> \
  --format markdown \
  --output guardrail-comment.md
terraform-guardrail enterprise report <evaluation-result-id> \
  --format sarif \
  --output guardrail-report.sarif
terraform-guardrail enterprise report <evaluation-result-id> \
  --format junit \
  --output guardrail-report.junit.xml
terraform-guardrail enterprise remediation create <evaluation-result-id> \
  --format markdown \
  --output guardrail-remediation.md
terraform-guardrail enterprise remediation patch-bundle <plan-id>
terraform-guardrail enterprise remediation patch-bundles --plan-id <plan-id>
terraform-guardrail enterprise remediation github-pr <bundle-id> \
  --repository Huzefaaa2/terraform-guardrail
terraform-guardrail enterprise remediation github-prs --bundle-id <bundle-id>
terraform-guardrail enterprise health
terraform-guardrail enterprise schedule create \
  --name daily-prod \
  --path ./infra \
  --cadence daily \
  --provider aws \
  --context environment=prod \
  --context risk_tier=high
terraform-guardrail enterprise schedule run <target-id>
terraform-guardrail enterprise schedule runs --target-id <target-id>
terraform-guardrail evidence schedule create \
  --name monthly-payments \
  --cadence monthly \
  --format json \
  --repo payments-infra
terraform-guardrail evidence schedule run <schedule-id>
terraform-guardrail evidence schedule runs --schedule-id <schedule-id>
terraform-guardrail enterprise automation run
terraform-guardrail enterprise automation runs
terraform-guardrail enterprise waiver create \
  --rule-id TG011 \
  --reason "Legacy module migration" \
  --owner platform-security \
  --expires-at 2026-12-31T00:00:00Z
terraform-guardrail enterprise waiver approve <waiver-id> --actor security-reviewer
terraform-guardrail enterprise waiver list --status approved
terraform-guardrail enterprise waiver revoke <waiver-id> --actor security-reviewer
```
