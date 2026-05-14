# How To Use the v1 Foundation Streamlit App

Use this app when you want a fast Terraform scan without enterprise setup.

Live app: https://terraform-guardrail.streamlit.app/

## What this app demonstrates

- TG001-TG023 rule detection on Terraform files.
- Optional Terraform state leak checks.
- CSV findings export.
- Links to the v2 Enterprise, v3-v5 Governance, and v1-v5 Full platform apps.

## Step by step

1. Open the v1 Foundation app.
2. Upload one or more `.tf`, `.tfvars`, or `.hcl` files.
3. Optionally upload a `.tfstate` file if you want state leak detection.
4. Keep schema-aware validation off unless Terraform CLI is available in the runtime.
5. Click **Scan**.
6. Review rule ID, severity, message, path, and detail.
7. Download the CSV findings file if you want to attach results to a ticket or review.

## When to move to another app

- Use the v2 Enterprise app when you need policy metadata, approvals, baselines, drift, or evidence.
- Use the v3-v5 Governance app when you need policy packs, explainability, remediation, and schedules.
- Use the v1-v5 Full platform app when you want the complete workflow in one GUI.
