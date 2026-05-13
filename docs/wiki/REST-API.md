# REST API

Terraform Guardrail Multi-Cloud Policy (MCP) (TerraGuard) exposes a REST API for CI/CD usage and UI integrations.

## Purpose

- Validate Terraform configs and state outside of Terraform.
- Provide consistent guardrail results for pipelines and dashboards.
- Power the Streamlit UI and registry workflows.
- Install enterprise policy packs and evaluate changes against approved baselines.

## Core Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /scan` | Scan Terraform files, directories, and optional state files |
| `POST /evaluate` | Run enterprise evaluation and return pass/warn/block |
| `POST /service/evaluate` | Run service-style evaluation with request ID, policy pack context, and evidence links |
| `GET /results/{result_id}` | Read a stored enterprise evaluation result |
| `GET /results/{result_id}/explain` | Explain why an evaluation passed, warned, or blocked |
| `GET /results/{result_id}/comment` | Render an explainability report as Markdown for CI/PR comments |
| `GET /results/{result_id}/reports/sarif` | Render enterprise evaluation findings as SARIF |
| `GET /results/{result_id}/reports/junit` | Render enterprise evaluation findings as JUnit XML |
| `POST /exports` | Export evidence for an evaluation |
| `POST /drift/check` | Compare current findings against a stored snapshot |
| `POST /drift/gate` | Combine enterprise evaluation, drift detection, and optional evidence |
| `GET /packs` | List built-in v3 enterprise policy packs |
| `GET /packs/{pack_id}` | Inspect a policy pack and its templates |
| `POST /packs/{pack_id}/install` | Install a policy pack into the enterprise store |
| `GET /risk-profiles` | List built-in and saved v4 context risk profiles |
| `POST /risk-profiles` | Create a custom context risk profile |
| `GET /risk-profiles/{profile_id}` | Inspect a context risk profile |
| `GET /recommendations` | List rule remediation and suggested fixes |
| `GET /recommendations/{rule_id}` | Inspect suggested fixes for one rule |
| `POST /waivers` | Request a time-bound policy waiver |
| `GET /waivers` | List waiver requests and approvals |
| `POST /waivers/{waiver_id}/approve` | Approve a waiver |
| `POST /waivers/{waiver_id}/revoke` | Revoke a waiver |
| `POST /remediation/plans` | Create a v5 remediation plan from an evaluation |
| `GET /remediation/plans` | List remediation plans |
| `GET /remediation/plans/{plan_id}` | Inspect a remediation plan |
| `GET /remediation/plans/{plan_id}/markdown` | Render a remediation plan as Markdown |
| `POST /remediation/patch-bundles` | Generate a PR-ready patch bundle scaffold |
| `GET /remediation/patch-bundles` | List patch bundle scaffolds |
| `GET /remediation/patch-bundles/{bundle_id}` | Inspect a patch bundle scaffold |
| `POST /remediation/patch-bundles/{bundle_id}/github-pr` | Plan or create a GitHub pull request from a patch bundle |
| `GET /remediation/github-prs` | List GitHub pull request records |
| `GET /governance/health` | Summarize governance health and recurring risk |
| `GET /governance/trends` | Return chart-ready waiver, evidence, remediation, and PR trend data |
| `POST /scheduled-scans` | Create a scheduler-ready governance scan target |
| `GET /scheduled-scans` | List scheduled scan targets |
| `GET /scheduled-scans/{target_id}` | Inspect a scheduled scan target |
| `POST /scheduled-scans/{target_id}/run` | Run a scheduled target on demand |
| `GET /scheduled-scans/{target_id}/runs` | List runs for a scheduled target |
| `POST /evidence/schedules` | Create a recurring evidence export schedule |
| `GET /evidence/schedules` | List evidence schedules |
| `GET /evidence/schedules/{schedule_id}` | Inspect an evidence schedule |
| `POST /evidence/schedules/{schedule_id}/run` | Run an evidence schedule on demand |
| `GET /evidence/schedules/{schedule_id}/runs` | List runs for an evidence schedule |
| `POST /automation/run` | Run enabled scheduled scans and evidence schedules |
| `GET /automation/runs` | List automation runner history |

## Policy Pack Install Example

```bash
curl -X POST http://localhost:8080/packs/pci-dss/install \
  -H 'content-type: application/json' \
  -d '{"actor":"platform-security","approve":true,"create_baseline":true}'
```

## Service Evaluation Example

```bash
curl -X POST http://localhost:8080/service/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "path":"./infra",
    "request_id":"github-run-12345",
    "provider":"aws",
    "policy_pack":"aws-control-tower",
    "context":{"repo":"payments-infra","environment":"prod"},
    "fail_on":"high",
    "evidence_format":"json",
    "actor":"github-actions"
  }'
```

## Context-Aware Evaluation Example

```bash
curl -X POST http://localhost:8080/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "path":"./infra",
    "provider":"aws",
    "context":{"repo":"payments-infra","environment":"prod","risk_tier":"high"}
  }'
```

The response includes `service_metadata.intelligence` with the matched risk profile, severity
adjustments, and suggested fixes.

## Status

Delivered as part of the Dockerized Multi-Cloud Policy (MCP) + REST API milestone and extended
in v3.0 development with policy pack and Guardrails-as-a-Service endpoints. v4.0 development adds
context risk profiles and recommendation endpoints. v5.0 development adds remediation plans,
patch bundle scaffolds, GitHub pull request records, governance health reporting, scheduled scan
target APIs, and evidence schedule APIs. The governance trends endpoint powers v5 dashboard charts.
The v5 background runner scaffold executes enabled scan and evidence schedules from one external
scheduler entrypoint.
