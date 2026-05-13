# Explainability Reports

Explainability reports show why an evaluation passed, warned, or blocked. They connect the final
decision to findings, context-aware severity changes, resolved policies, baselines, and suggested
next actions.

## Status

Delivered in v4.0 development.

## What It Does

- Explains the final `pass`, `warn`, or `block` decision.
- Lists resolved policy IDs, policy metadata, binding targets, and baseline IDs.
- Shows the matched risk profile and context severity adjustments.
- Shows approved waivers that changed the decision.
- Explains each finding with the associated policy, remediation, and suggested fix.
- Produces next actions that can be used in CI logs, PR comments, or audit packets.

## CLI

```bash
terraform-guardrail evaluate ./infra \
  --context environment=prod \
  --context risk_tier=high \
  --format json
```

Use the returned evaluation ID:

```bash
terraform-guardrail enterprise explain <evaluation-result-id>
terraform-guardrail enterprise explain <evaluation-result-id> --format json
terraform-guardrail enterprise explain <evaluation-result-id> \
  --format markdown \
  --output guardrail-comment.md
```

## API

```http
GET /results/{result_id}/explain
GET /results/{result_id}/comment
```

The response includes:

- `reasons`
- `applied_policies`
- `baseline_ids`
- `risk_profile`
- `context_adjustments`
- `finding_explanations`
- `next_actions`

`/comment` returns a Markdown body intended for CI logs, PR comments, merge request comments, or
pipeline summary artifacts.

## Example

```json
{
  "decision": "block",
  "reasons": [
    "High-severity findings require blocking before apply.",
    "Context-aware evaluation raised one or more finding severities."
  ],
  "next_actions": [
    "TG011: Add an `aws_s3_bucket_server_side_encryption_configuration` resource."
  ]
}
```

## CI Comment Artifact

The v3 reference implementations now render a v4 Markdown comment artifact:

- `examples/github-actions/guardrails-service-v3.yml`
- `examples/gitlab-ci/service-v3.gitlab-ci.yml`
- `examples/azure-devops/service-v3.yml`
- `examples/aws-codepipeline/buildspec-service-v3.yml`

Each example writes `guardrail-comment.md` alongside `guardrail-service-response.json` and evidence
artifacts.
