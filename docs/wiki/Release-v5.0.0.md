# v5.0.0 Autonomous Governance Release

v5.0.0 moves Terraform Guardrail from explaining governance decisions to operating the governance
loop. It keeps the v2 enterprise control plane, v3 ecosystem layer, and v4 intelligence features,
then adds remediation workflows, scheduled governance, GitHub PR automation, evidence scheduling,
and dashboard trends.

## Release Links

- GitHub Release: https://github.com/Huzefaaa2/terraform-guardrail/releases/tag/v5.0.0
- PyPI: https://pypi.org/project/terraform-guardrail/5.0.0/
- README: https://github.com/Huzefaaa2/terraform-guardrail
- Roadmap: [Roadmap](Roadmap)
- Guide: [Autonomous Governance](Autonomous-Governance)

## What Is New

| Capability | Delivered behavior |
| --- | --- |
| Remediation plans | Converts stored evaluation results into reviewable actions with suggested fixes and Terraform snippet previews. |
| PR-ready patch bundles | Generates branch metadata, commit messages, `PULL_REQUEST.md`, manifests, and Terraform snippet files. |
| GitHub PR automation | Records safe dry-run PR plans by default and can call `gh pr create` when explicitly requested. |
| Scheduled scans | Stores recurring governance scan targets with path, cadence, provider, baseline, fail threshold, and context. |
| Evidence scheduling | Defines recurring JSON, CSV, or PDF audit exports by result, context, standard, or control. |
| Background runner | Executes enabled scan and evidence schedules from a cron, CI, CodeBuild, or platform orchestrator entrypoint. |
| Governance health | Summarizes decisions, recurring rules, waivers, evidence, remediation plans, PR records, and risk signals. |
| Trend dashboard | Charts waiver aging, evidence coverage, remediation flow, PR activity, and 7-day governance activity. |

## CLI Highlights

```bash
terraform-guardrail evaluate ./infra \
  --context environment=prod \
  --context risk_tier=high \
  --format json
```

```bash
terraform-guardrail enterprise remediation create <result-id> \
  --format markdown \
  --output guardrail-remediation.md

terraform-guardrail enterprise remediation patch-bundle <plan-id>

terraform-guardrail enterprise remediation github-pr <bundle-id> \
  --repository Huzefaaa2/terraform-guardrail
```

```bash
terraform-guardrail enterprise schedule create \
  --name daily-prod \
  --path ./infra \
  --cadence daily \
  --provider aws \
  --context environment=prod

terraform-guardrail evidence schedule create \
  --name monthly-soc2 \
  --standard SOC2 \
  --format json \
  --repo payments-infra

terraform-guardrail enterprise automation run
terraform-guardrail enterprise trends
```

## API Highlights

- `POST /remediation/plans`
- `POST /remediation/patch-bundles`
- `POST /remediation/patch-bundles/{bundle_id}/github-pr`
- `GET /governance/health`
- `GET /governance/trends`
- `POST /scheduled-scans`
- `POST /scheduled-scans/{target_id}/run`
- `POST /evidence/schedules`
- `POST /evidence/schedules/{schedule_id}/run`
- `POST /automation/run`

## Verification

The v5.0.0 release hardening path verifies:

- Full test suite.
- Ruff linting.
- Source distribution and wheel build.
- Wheel installation smoke test.
- CLI version and enterprise command smoke tests.
- GitHub Actions CI on `main`.

## Upgrade Notes

- Existing v1-v4 CLI, REST API, web UI, Streamlit, MCP, registry, policy bundle, and evidence flows remain backward compatible.
- Enterprise data still defaults to `.guardrail/enterprise` and can be overridden with `GUARDRAIL_ENTERPRISE_DATA_DIR`.
- GitHub PR automation is dry-run by default; use `--create` only after the remediation branch has been prepared and pushed.
- Windows installation is through PyPI: `py -m pip install terraform-guardrail`.
