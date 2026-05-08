# v2.0.0 Enterprise Release

v2.0.0 is the Enterprise Foundation release for Terraform Guardrail Multi-Cloud Policy
(TerraGuard). It adds a complete governance workflow around the existing scanner, registry, API,
CLI, and web UI.

## Release Status

- GitHub Release: https://github.com/Huzefaaa2/terraform-guardrail/releases/tag/v2.0.0
- PyPI: https://pypi.org/project/terraform-guardrail/2.0.0/
- Container image: `ghcr.io/huzefaaa2/terraform-guardrail:v2.0.0`
- Registry image: `ghcr.io/huzefaaa2/terraform-guardrail-registry:v2.0.0`
- Homebrew, Chocolatey, packaging, container, registry image, and CI workflows completed for the
  release.

## What Shipped

| Roadmap item | v2.0.0 status | Details |
| --- | --- | --- |
| AWS CodePipeline + CodeBuild integration | Delivered | [AWS CodePipeline](AWS-CodePipeline) |
| Policy authoring UI | Delivered | [Policy Authoring UI](Policy-Authoring-UI) |
| Policy metadata + rich failure messages | Delivered | [Policy Metadata](Policy-Metadata) |
| Drift-prevention rules before apply | Delivered | [Drift Prevention](Drift-Prevention) |
| Org-wide baselines | Delivered | [Org-Wide Baselines](Org-Wide-Baselines) |
| Group-level enforcement | Delivered | [Group-Level Enforcement](Group-Level-Enforcement) |
| Evidence export (SOC2 / ISO / PCI) | Delivered | [Evidence Export](Evidence-Export) |

## Enterprise Foundation

v2.0.0 introduces a JSON-backed enterprise domain model:

- Policies, versions, and approvals
- Policy metadata for owner, standard, control ID, risk, expiry, and remediation
- Org baselines and baseline approvals
- Org, group, and repo bindings with inheritance-aware resolution
- Evaluation results with pass/warn/block decisions
- Drift snapshots, drift checks, and drift gates
- Evidence exports in JSON, CSV, and PDF
- Audit events for lifecycle actions

The default enterprise data directory is `.guardrail/enterprise`. Override it with:

```bash
export GUARDRAIL_ENTERPRISE_DATA_DIR=/path/to/enterprise-store
```

## Main Commands

```bash
terraform-guardrail evaluate ./infra --provider aws --baseline org-baseline --format json
terraform-guardrail enterprise policy create --name "Production S3 encryption"
terraform-guardrail enterprise baseline create --name org-baseline --policy-id pol_example
terraform-guardrail enterprise binding create --target-type group --target platform --policy-id pol_example
terraform-guardrail enterprise drift-gate ./infra --snapshot-id prod --evidence-format pdf
terraform-guardrail evidence export <result-id> --format json
terraform-guardrail enterprise aws codepipeline init --destination aws-codepipeline-guardrail
```

## Main API Areas

- `/policies`
- `/policies/{id}/versions`
- `/policies/{id}/approve`
- `/policies/{id}/preview`
- `/baselines`
- `/bindings`
- `/evaluate`
- `/drift/check`
- `/drift/gate`
- `/exports`

## Recommended Reading

- [How-To Guides](How-To-Guides)
- [Roadmap](Roadmap)
- [Diagrams](Diagrams)
- [Enterprise Features](Enterprise-Features)
- [AWS CodePipeline](AWS-CodePipeline)
- [Evidence Export](Evidence-Export)
