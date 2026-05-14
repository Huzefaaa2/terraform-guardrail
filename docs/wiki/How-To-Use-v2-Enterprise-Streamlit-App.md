# How To Use the v2 Enterprise Streamlit App

Use this app when you want to understand enterprise policy authoring, policy metadata, drift gates,
and evidence export.

Live app: https://terraform-guardrail-enterprise.streamlit.app/

## What this app demonstrates

- Enterprise evaluation with pass/warn/block decisions.
- Default rule catalog with clickable TG rule IDs.
- Copyable and downloadable policy snippets.
- Policy metadata such as owner, standard, control ID, risk, and remediation.
- Drift gate simulation before apply.
- JSON, CSV, and PDF evidence export.

## Step by step

1. Open the v2 Enterprise app.
2. In **Enterprise Evaluation**, use the sample Terraform or upload your own files.
3. Choose provider, environment, risk tier, baseline, group, repo, and `fail-on`.
4. Click **Run Enterprise Evaluation**.
5. Review the decision, resolved policy IDs, suggested fixes, waivers, and findings.
6. Download evidence in JSON, CSV, or PDF.
7. Open **Policy Catalog**.
8. Click any TG rule ID to read the rule, risk, remediation, suggested fix, and policy snippet.
9. Use **Download rule snippet** when you want to keep or adapt the rule metadata.
10. Open **Drift Gate** to compare an approved snapshot with a current change.
11. Open **CI Evidence** to copy the AWS CodePipeline/CodeBuild command pattern.

## Recommended next step

After learning v2, open the v3-v5 Governance app to see policy packs, explainability,
remediation plans, PR dry runs, scheduled scans, and governance health.
