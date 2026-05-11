# Guardrails-as-a-Service API

Guardrails-as-a-Service is the v3.0 service contract for CI/CD systems that need a stable
pass/warn/block response, resolved policy context, and evidence links from one call.

## Delivered in v3.0 Development

- Stable service endpoint: `POST /service/evaluate`.
- Caller-supplied `request_id` for CI traceability.
- Optional policy pack resolution and installation.
- Baseline-aware enterprise evaluation.
- Optional JSON, CSV, or PDF evidence export.
- Stable result and evidence links.
- Stored evaluation includes request ID and service metadata.

## Request

```http
POST /service/evaluate
```

```json
{
  "path": "./infra",
  "request_id": "github-run-12345",
  "provider": "aws",
  "policy_pack": "aws-control-tower",
  "baseline": null,
  "context": {
    "repo": "payments-infra",
    "environment": "prod"
  },
  "fail_on": "high",
  "evidence_format": "json",
  "actor": "github-actions"
}
```

If `policy_pack` is provided, TerraGuard installs the pack once and reuses the installed baseline
on later calls. If `baseline` is also provided, the explicit baseline wins.

## Response

```json
{
  "request_id": "github-run-12345",
  "result_id": "eval_...",
  "decision": "block",
  "status": "completed",
  "summary": {
    "findings": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "links": {
    "result": "/results/eval_...",
    "evidence": "/exports/evid_..."
  },
  "resolved": {
    "baseline": "base_...",
    "policy_pack": "aws-control-tower",
    "policy_pack_install_id": "pack_install_...",
    "policy_ids": ["pol_..."]
  }
}
```

## CI Behavior

- Treat `decision=block` as a failed pipeline gate.
- Treat `decision=warn` as a non-blocking warning unless your rollout mode requires strict gates.
- Store the `result` and `evidence` links as build artifacts or PR comments.
- Use `request_id` to join Terraform plan runs, TerraGuard results, and audit evidence.

## Status

Delivered as the second v3.0 Ecosystem capability.
