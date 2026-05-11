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
| `POST /exports` | Export evidence for an evaluation |
| `POST /drift/check` | Compare current findings against a stored snapshot |
| `POST /drift/gate` | Combine enterprise evaluation, drift detection, and optional evidence |
| `GET /packs` | List built-in v3 enterprise policy packs |
| `GET /packs/{pack_id}` | Inspect a policy pack and its templates |
| `POST /packs/{pack_id}/install` | Install a policy pack into the enterprise store |

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

## Status

Delivered as part of the Dockerized Multi-Cloud Policy (MCP) + REST API milestone and extended
in v3.0 development with policy pack and Guardrails-as-a-Service endpoints.
