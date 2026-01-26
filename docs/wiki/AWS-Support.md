# AWS Support

Terraform-Guardrail provides **first-class support for AWS environments** and is designed to
complement AWS-native governance services by enforcing **pre-deployment, IaC-aware guardrails**.

Unlike AWS-native controls that operate post-deployment or at the account boundary,
Terraform-Guardrail enforces architectural, security, and compliance policies **before Terraform
apply**, directly inside CI/CD pipelines.

## Supported AWS CI/CD integrations

- **GitHub Actions** (primary AWS CI integration)
- **GitLab CI** (widely used in regulated AWS enterprises)
- **AWS CodePipeline + CodeBuild** (via buildspec integration)

## AWS-specific capabilities

- Pre-apply guardrail enforcement for Terraform targeting AWS
- Account- and environment-aware policy evaluation
- OU-aligned guardrails (designed to complement AWS Organizations)
- Shift-left enforcement for Control Tower-aligned environments
- Evidence generation for audits (SOC2, ISO, PCI)

Terraform-Guardrail enables platform teams to define **organization-wide AWS standards** and
ensure they are enforced consistently across accounts, pipelines, and teams — before infrastructure
reaches AWS.
