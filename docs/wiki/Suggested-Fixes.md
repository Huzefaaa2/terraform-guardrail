# Suggested Fixes + Recommendations

Suggested fixes turn rule failures into developer guidance. The first v4 implementation attaches
rule-level remediation and a concrete `suggested_fix` to scan findings and exposes a recommendation
catalog through the CLI and REST API.

## Status

Delivered in v4.0 development.

## What It Does

- Adds `suggested_fix` to each finding when the rule has remediation guidance.
- Keeps existing `rule_id`, `severity`, `message`, `path`, `detail`, `risk`, and `remediation`
  fields backward compatible.
- Adds the same suggestion into `finding.detail.suggested_fix` for clients that already render
  finding details.
- Returns recommendation summaries in `service_metadata.intelligence.recommendations`.

## CLI

```bash
terraform-guardrail enterprise recommendations
terraform-guardrail enterprise recommendations --rule-id TG011
```

Example output:

```text
TG011: Add an `aws_s3_bucket_server_side_encryption_configuration` resource.
```

## API

- `GET /recommendations`
- `GET /recommendations/{rule_id}`

Example:

```bash
curl http://localhost:8080/recommendations/TG011
```

## Evaluation Output

```json
{
  "rule_id": "TG011",
  "severity": "high",
  "remediation": "Enable S3 default encryption with KMS or AES256.",
  "suggested_fix": "Add an `aws_s3_bucket_server_side_encryption_configuration` resource."
}
```

## UI Rendering

The FastAPI web UI and Streamlit enterprise demo render suggested fixes next to the affected
finding, so developers can move from a blocked evaluation to the likely Terraform change without
opening raw JSON.
