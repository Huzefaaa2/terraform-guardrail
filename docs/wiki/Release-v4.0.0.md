# v4.0.0 Intelligent Release

v4.0.0 turns Terraform Guardrail from an enterprise control plane into an intelligent governance
assistant. It keeps the v2 enterprise workflow and v3 ecosystem integrations, then adds contextual
decisions, remediation guidance, explainability, CI-native report formats, and controlled policy
waivers.

## Release Links

- GitHub Release: https://github.com/Huzefaaa2/terraform-guardrail/releases/tag/v4.0.0
- PyPI: https://pypi.org/project/terraform-guardrail/4.0.0/
- README: https://github.com/Huzefaaa2/terraform-guardrail
- Roadmap: [Roadmap](Roadmap)

## What Is New

| Capability | Delivered behavior |
| --- | --- |
| Context-aware evaluation | Applies risk profiles using environment and risk tier context, records matched profile metadata, and adjusts severity/fail-on behavior. |
| Suggested fixes | Adds remediation guidance to rule findings and exposes recommendations through CLI, REST API, Web UI, and Streamlit. |
| Explainability reports | Produces decision reasons, finding explanations, next actions, and CI-friendly Markdown comments from stored evaluation results. |
| SARIF/JUnit bridge | Converts enterprise evaluations into SARIF for code scanning and JUnit XML for CI test report surfaces. |
| Policy waivers | Supports approved, expiring exceptions with audit events, evaluation suppression, report visibility, and Web UI/Streamlit controls. |

## CLI Highlights

```bash
terraform-guardrail evaluate ./infra \
  --context environment=prod \
  --context risk_tier=high \
  --format json
```

```bash
terraform-guardrail enterprise explain <result-id> --format markdown \
  --output guardrail-comment.md

terraform-guardrail enterprise report <result-id> \
  --format sarif \
  --output guardrail-report.sarif

terraform-guardrail enterprise waiver create \
  --rule-id TG011 \
  --owner platform-team \
  --reason "Temporary migration exception" \
  --expires-at 2026-06-30T00:00:00Z
```

## API Highlights

- `GET /risk-profiles`
- `POST /risk-profiles`
- `GET /recommendations`
- `GET /results/{result_id}/explain`
- `GET /results/{result_id}/comment`
- `GET /results/{result_id}/reports/sarif`
- `GET /results/{result_id}/reports/junit`
- `POST /waivers`
- `GET /waivers`
- `POST /waivers/{waiver_id}/approve`
- `POST /waivers/{waiver_id}/revoke`

## CI Artifacts

The v3 service reference implementations now also produce:

- `guardrail-comment.md` for pull request or pipeline summaries.
- `guardrail-report.sarif` for code scanning dashboards.
- `guardrail-report.junit.xml` for CI test result views.
- Evidence JSON/CSV/PDF artifacts from the existing enterprise export flow.

## Documentation

- [Context-Aware Evaluation](Context-Aware-Evaluation)
- [Suggested Fixes](Suggested-Fixes)
- [Explainability Reports](Explainability-Reports)
- [Enterprise SARIF/JUnit](Enterprise-SARIF-JUnit)
- [Policy Waivers](Policy-Waivers)
