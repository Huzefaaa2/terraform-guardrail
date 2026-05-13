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

## Next v5 Steps

- Scheduled scans across configured repositories or folders.
- Remediation pull request automation.
- Evidence scheduling by app, group, standard, or control.
- Dashboard trend charts for waiver aging and evidence coverage.
