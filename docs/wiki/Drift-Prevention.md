# Drift Prevention

Drift prevention blocks unsafe changes before Terraform mutates infrastructure. The v2 enterprise
flow combines policy evaluation, drift snapshot comparison, and optional evidence export in one
CI-friendly gate.

## CLI

Create the initial approved snapshot and export evidence:

```bash
terraform-guardrail enterprise drift-gate ./infra \
  --snapshot-id prod \
  --provider aws \
  --baseline org-baseline \
  --evidence-format pdf
```

On later runs, the same command compares current findings against the stored snapshot. If drift is
detected, the command exits non-zero and returns a block decision.

Use strict mode when the snapshot must already exist:

```bash
terraform-guardrail enterprise drift-gate ./infra \
  --snapshot-id prod \
  --no-create-snapshot
```

## API

```http
POST /drift/gate
```

Example request:

```json
{
  "path": "./infra",
  "snapshot_id": "prod",
  "provider": "aws",
  "baseline": "org-baseline",
  "evidence_format": "pdf"
}
```

## Decision behavior

- `block` when enterprise evaluation blocks.
- `block` when drift is detected against the snapshot.
- `warn` when policy findings are warning-level but no drift is detected.
- `pass` when there are no blocking findings and no drift.

## Status

Implemented foundation: drift snapshots, drift checks, drift gate CLI/API, evidence export, and
non-zero CI exit behavior on drift.
