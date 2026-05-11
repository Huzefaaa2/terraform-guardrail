# v3.0.0 Ecosystem Development

v3.0.0 expands Terraform Guardrail from an enterprise control plane into an ecosystem layer:
curated policy packs, reference implementations, cross-provider invariants, a stronger
Guardrails-as-a-Service API, and public contributor governance.

## Implementation Sequence

1. Enterprise policy packs.
2. Guardrails-as-a-Service API hardening.
3. Cross-provider invariant enforcement.
4. Reference implementations across common tools.
5. Contributor governance and public roadmap workflows.

## Current Status

| Capability | Status | Notes |
| --- | --- | --- |
| Enterprise policy packs | Delivered | Built-in pack catalog, CLI/API install, baseline creation, audit event |
| Guardrails-as-a-Service API | Next | Harden `/evaluate` for service-style CI use and evidence links |
| Cross-provider invariant enforcement | Planned | Shared controls across AWS, Azure, and GCP patterns |
| Reference implementations across tools | Planned | End-to-end examples for GitHub, GitLab, Azure DevOps, AWS CodePipeline |
| Contributor governance + public roadmap | Planned | Issue templates, contribution workflow, roadmap hygiene |

## Delivered: Enterprise Policy Packs

The first v3.0 capability adds built-in policy packs for:

- `pci-dss`
- `aws-control-tower`
- `azure-landing-zone`
- `banking-resiliency`

Each pack includes versioned metadata, provider scope, standards mapping, enterprise policy
templates, and an install path that creates approved policies and a baseline.

```bash
terraform-guardrail enterprise pack list
terraform-guardrail enterprise pack show pci-dss
terraform-guardrail enterprise pack install pci-dss --actor platform-security
```

REST endpoints:

- `GET /packs`
- `GET /packs/{pack_id}`
- `POST /packs/{pack_id}/install`

Detailed guide: [Policy Packs](Policy-Packs).
