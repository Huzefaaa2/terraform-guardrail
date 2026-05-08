# Evidence Export

Evidence export creates audit-ready artifacts for SOC2, ISO, PCI, and internal governance
workflows.

## Supported formats

- JSON
- CSV
- PDF

## CLI

Run an enterprise evaluation:

```bash
terraform-guardrail evaluate ./infra --provider aws --baseline org-baseline --format json
```

Export evidence from the returned result ID:

```bash
terraform-guardrail evidence export <result-id> --format json
terraform-guardrail evidence export <result-id> --format csv
terraform-guardrail evidence export <result-id> --format pdf
```

## API

```http
POST /exports
GET /exports/{export_id}
```

Example request:

```json
{
  "result_id": "eval_example",
  "format": "pdf"
}
```

## Evidence contents

Evidence artifacts include:

- Evaluation ID and timestamp
- Pass/warn/block decision
- Provider, baseline, org, group, repo, and environment context
- Resolved policy IDs
- Finding summary
- Finding details with owner, standard, control ID, risk, and remediation when available

## Status

Implemented foundation: JSON, CSV, and dependency-free PDF evidence exports with traceable
timestamps and immutable export records.
