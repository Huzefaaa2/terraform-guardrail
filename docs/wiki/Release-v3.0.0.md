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
| Guardrails-as-a-Service API | Delivered | `/service/evaluate` contract with request ID, pack context, evidence links |
| Cross-provider invariant enforcement | Delivered | TG021-TG023 common exposure, encryption, and ownership controls |
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

## Delivered: Guardrails-as-a-Service API

The second v3.0 capability adds a CI-friendly service contract:

```bash
curl -X POST http://localhost:8080/service/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "path":"./infra",
    "request_id":"github-run-12345",
    "provider":"aws",
    "policy_pack":"aws-control-tower",
    "fail_on":"high",
    "evidence_format":"json",
    "actor":"github-actions"
  }'
```

The response includes a stable request ID, result ID, pass/warn/block decision, resolved policy
pack and baseline context, and links to stored result and evidence records.

Detailed guide: [Guardrails-as-a-Service API](Guardrails-as-a-Service).

## Delivered: Cross-Provider Invariant Enforcement

The third v3.0 capability adds provider-normalized controls:

- `TG021`: public exposure invariant.
- `TG022`: storage encryption invariant.
- `TG023`: ownership metadata invariant.

These findings carry `detail.invariant`, `detail.provider`, and `detail.resource` so policy packs,
service API consumers, and evidence exports can reason about common controls across AWS, Azure, and
GCP.

Detailed guide: [Cross-Provider Invariants](Cross-Provider-Invariants).
