# Terraform-Guardrail with AWS CodePipeline (Reference Architecture)

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

## What this enables

- Terraform-aware policy gates in CodePipeline
- Blocking non-compliant infrastructure before apply
- Audit-ready evidence for AWS environments
- Alignment with AWS Organizations & Control Tower
