# v5.0 Autonomous Governance

v5.0 moves Terraform Guardrail from explaining governance decisions to helping operate the
governance program. The first foundation adds remediation plans and governance health reporting on
top of v4 evaluation, explainability, evidence, and waiver data.

## Remediation Plans

Create a remediation plan from a stored evaluation result:

```bash
terraform-guardrail enterprise remediation create <result-id>
```

Generate Markdown for a pull request, work item, or audit note:

```bash
terraform-guardrail enterprise remediation create <result-id> \
  --format markdown \
  --output guardrail-remediation.md
```

The plan includes rule ID, severity, path, suggested fix, Terraform snippet preview for common safe
fixes, confidence level, and skipped findings when an approved waiver is active.

API:

- `POST /remediation/plans`
- `GET /remediation/plans`
- `GET /remediation/plans/{plan_id}`
- `GET /remediation/plans/{plan_id}/markdown`

## Governance Health

Governance health summarizes stored enterprise activity:

```bash
terraform-guardrail enterprise health
terraform-guardrail enterprise health --format json
```

API:

- `GET /governance/health`

The report includes total evaluations, findings, policies, baselines, remediation plans,
pass/warn/block counts, top recurring rules, waiver summary, evidence summary, and risk signals.

## Web UI Dashboard

The Enterprise web workspace includes a **Governance health dashboard** at the top of the page. It
shows evaluation, finding, blocked-decision, waiver, evidence, and remediation-plan counts, plus top
recurring rules, current risk signals, and latest remediation plans.

After a scan, select **Create Remediation Plan** in the evaluation report to generate a v5 plan from
the stored result. The page displays reviewable actions, suggested fixes, confidence, and Terraform
snippet previews when a common safe fix is available.

## Scheduled Governance Scans

v5 includes a scheduler-ready configuration layer for recurring governance scans. A target defines
the Terraform path, cadence, provider, baseline, fail threshold, and context. The current foundation
stores the schedule and supports manual execution; a later step can attach a background runner or
external orchestrator.

Create a target:

```bash
terraform-guardrail enterprise schedule create \
  --name daily-prod \
  --path ./infra \
  --cadence daily \
  --provider aws \
  --context environment=prod \
  --context risk_tier=high
```

Run it on demand:

```bash
terraform-guardrail enterprise schedule run <target-id>
terraform-guardrail enterprise schedule runs --target-id <target-id>
```

API:

- `POST /scheduled-scans`
- `GET /scheduled-scans`
- `GET /scheduled-scans/{target_id}`
- `POST /scheduled-scans/{target_id}/run`
- `GET /scheduled-scans/{target_id}/runs`

## Remediation Pull Request Scaffold

The first PR automation step is provider-neutral. Terraform Guardrail generates branch/commit
metadata, a pull request body, a manifest, and Terraform snippet files from a remediation plan. It
does not open a pull request yet; teams can review the artifact directory or wire it into their own
GitHub, GitLab, or Azure DevOps automation.

```bash
terraform-guardrail enterprise remediation patch-bundle <plan-id>
terraform-guardrail enterprise remediation patch-bundles --plan-id <plan-id>
```

The bundle includes:

- Branch name such as `guardrail/remediate/eval-...`.
- Commit message.
- `PULL_REQUEST.md`.
- `manifest.json`.
- Generated Terraform snippet files under `terraform-guardrail-remediation/`.

API:

- `POST /remediation/patch-bundles`
- `GET /remediation/patch-bundles`
- `GET /remediation/patch-bundles/{bundle_id}`

## Next v5 Steps

- GitHub pull request creation from patch bundles.
- Evidence scheduling by app, group, standard, or control.
- Dashboard trend charts for waiver aging and evidence coverage.
