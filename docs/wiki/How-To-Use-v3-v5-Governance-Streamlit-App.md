# How To Use the v3-v5 Governance Streamlit App

Use this app when you want to see the connected enterprise loop from policy packs to autonomous
governance.

Live app: https://terraform-guardrail-governance.streamlit.app/

## What this app demonstrates

- v3 policy packs and installable baselines.
- v4 context-aware evaluation, explainability, suggested fixes, SARIF, and JUnit.
- v5 remediation plans, patch bundles, GitHub PR dry runs, scheduled scans, evidence schedules,
  automation runner output, health, and trends.

## Step by step

1. Open the v3-v5 Governance app.
2. In the sidebar, select a policy pack such as PCI DSS or AWS Control Tower.
3. Choose provider, environment, risk tier, application, group, repo, and `fail-on`.
4. Use the sample Terraform or upload one or more Terraform files.
5. Click **Run Governance Loop**.
6. In **v3 Ecosystem**, review the installed pack and resolved baseline.
7. In **v4 Intelligence**, review the decision, risk profile, context adjustments, findings,
   suggested fixes, and explainability report.
8. In **v5 Autonomous**, review remediation actions, patch previews, PR dry-run command,
   scheduled scan, evidence schedule, and automation runner output.
9. In **Evidence + Health**, download JSON evidence, CSV evidence, SARIF, or JUnit and review
   governance health signals.

## Why this is one app

v3, v4, and v5 are strongest together. Policy packs feed intelligent decisions, intelligent
decisions feed remediation, and remediation plus scheduled evidence turns governance into a loop.
