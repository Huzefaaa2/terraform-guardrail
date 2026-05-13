# Context-Aware Evaluation

Context-aware evaluation adjusts enforcement based on environment and risk signals. The first v4
implementation supports risk profiles backed by the enterprise JSON store, built-in production and
sandbox defaults, API/CLI management, and evaluation metadata that explains every severity
adjustment.

## Status

Delivered in v4.0 development.

## What It Does

- Resolves a risk profile from `context.environment`, `context.risk_tier`, or an explicit
  `context.risk_profile` / `context.risk_profile_id`.
- Escalates finding severity only when the matched profile is stricter than the base rule.
- Recomputes the scan summary after contextual severity changes.
- Records the matched profile, adjustments, and recommendations under
  `service_metadata.intelligence` and `report.metadata.intelligence`.
- Supports custom risk profiles in `.guardrail/enterprise/risk_profiles.json`.

## Built-In Profiles

| Profile | Match | Behavior |
| --- | --- | --- |
| `default-prod-high-risk` | `environment=prod|production` or `risk_tier=high|critical` | Treats encryption, public exposure, and ownership findings more strictly |
| `default-dev-sandbox` | `environment=dev|development|sandbox` or `risk_tier=low` | Keeps sandbox checks lenient while still reporting findings |

## CLI

```bash
terraform-guardrail evaluate ./infra \
  --context environment=prod \
  --context risk_tier=high \
  --format json
```

```bash
terraform-guardrail enterprise risk-profile create \
  --name regulated-prod \
  --environment prod \
  --risk-tier critical \
  --severity-override TG011=high \
  --default-fail-on medium
```

```bash
terraform-guardrail enterprise risk-profile list
terraform-guardrail enterprise risk-profile show default-prod-high-risk
```

## API

- `GET /risk-profiles`
- `POST /risk-profiles`
- `GET /risk-profiles/{profile_id}`
- `POST /evaluate` with `context.environment`, `context.risk_tier`, or
  `context.risk_profile`

Example:

```json
{
  "path": "./infra",
  "provider": "aws",
  "context": {
    "repo": "payments-infra",
    "environment": "prod",
    "risk_tier": "high"
  }
}
```

## Web UI and Streamlit

The FastAPI web UI upload panel includes provider, environment, risk-tier, baseline, and fail-on
controls. After evaluation, the report shows the matched risk profile, adjustment count, suggested
fix count, and each severity escalation.

The Streamlit enterprise demo exposes the same context controls and displays the matched risk
profile, context adjustments, recommendations, and enriched findings table.
