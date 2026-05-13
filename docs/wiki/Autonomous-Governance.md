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

## Next v5 Steps

- Scheduled scans across configured repositories or folders.
- Remediation pull request automation.
- Evidence scheduling by app, group, standard, or control.
- Governance dashboard UI for trends, waiver aging, and evidence coverage.
