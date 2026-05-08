# Terraform-Guardrail with AWS CodePipeline

## Problem AWS teams face

AWS CodePipeline does not provide a native policy gate or IaC guardrail mechanism. Terraform
governance is typically implemented using:

- Custom shell scripts
- Ad-hoc checks
- Post-deployment AWS Config rules

This leads to late detection, inconsistent enforcement, and audit friction.

## Reference Architecture (Textual)

Developer PR / Commit
        |
        v
AWS CodePipeline
  ├── Source Stage (GitHub / CodeCommit)
  ├── Guardrail Stage (CodeBuild)
  │     ├── terraform init
  │     ├── terraform plan
  │     └── terraform-guardrail evaluate
  │           ├── Fetch org guardrails
  │           ├── Apply AWS-specific policies
  │           └── Enforce pass / warn / block
  ├── Apply Stage (CodeBuild)
  │     └── terraform apply
  └── Evidence Artifacts
        └── Guardrail report (JSON / SARIF / PDF)

## Example CodeBuild buildspec.yml

```yaml
version: 0.2

phases:
  install:
    commands:
      - curl -fsSL https://guardrail.sh/install | bash
  pre_build:
    commands:
      - terraform init
      - terraform plan -out=tfplan
      - terraform-guardrail evaluate \
          --provider aws \
          --policy-set org-baseline \
          --input tfplan
  build:
    commands:
      - terraform apply -auto-approve tfplan
artifacts:
  files:
    - guardrail-report.json
```

The repository includes a runnable starter buildspec at
`examples/aws-codepipeline/buildspec.yml` and a sample evidence artifact at
`examples/aws-codepipeline/outputs/guardrail-evidence.json`.

## Generate a CodeBuild Guardrail Stage

Use the CLI scaffold command to generate a CodeBuild buildspec and README for your repository:

```bash
terraform-guardrail enterprise aws codepipeline init \
  --destination aws-codepipeline-guardrail \
  --terraform-dir infra \
  --baseline org-baseline \
  --evidence-format pdf
```

Generated files:

- `buildspec-guardrail.yml`
- `README.md`

By default, the generated buildspec acts as a guardrail-only stage. Terraform apply should remain in
a later CodePipeline stage. To include apply in the same buildspec:

```bash
terraform-guardrail enterprise aws codepipeline init --include-apply
```

For v2.0 Enterprise, the CodeBuild gate should call:

```bash
terraform-guardrail enterprise drift-gate . \
  --provider aws \
  --baseline org-baseline \
  --snapshot-id prod \
  --evidence-format pdf \
  --format json
```

For evaluation without drift snapshot enforcement:

```bash
terraform-guardrail evaluate . --provider aws --baseline org-baseline --format json
terraform-guardrail evidence export <evaluation-result-id> --format json
```

`drift-gate` records a pass/warn/block decision, compares against the approved drift snapshot, and
can export immutable JSON, CSV, or PDF evidence artifacts for audit workflows.

## What this enables

- Terraform-aware policy gates in CodePipeline
- Blocking non-compliant infrastructure before apply
- Audit-ready evidence for AWS environments
- Alignment with AWS Organizations & Control Tower
