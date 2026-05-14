# Enterprise Case Studies

These stories show common enterprise IaC governance problems and how Terraform Guardrail solves
them with a practical, step-by-step path.

## 1. The Audit Team That Always Chased Evidence

The challenge: A financial services team used Terraform heavily, but SOC2 and PCI evidence lived
in screenshots, spreadsheets, and ticket comments. Every audit cycle became a manual collection
project.

How Terraform Guardrail helps: Evaluations produce consistent findings, decisions, metadata,
and evidence exports. Evidence schedules in v5 make this repeatable.

Steps:

1. Install the tool:

   ```bash
   pip install terraform-guardrail
   ```

2. Run an enterprise evaluation:

   ```bash
   terraform-guardrail evaluate ./infra --provider aws --baseline org-baseline --format json
   ```

3. Export evidence:

   ```bash
   terraform-guardrail evidence export <result-id> --format json
   terraform-guardrail evidence export <result-id> --format csv
   ```

4. In the v1-v5 Full platform app, open **Evidence + Health** and download JSON, CSV, SARIF, or
   JUnit.

Outcome: Audit evidence becomes a product of delivery rather than a separate manual activity.

## 2. The Platform Team Blocking Public Exposure Before Apply

The challenge: A product team accidentally proposed a public S3 bucket and an open SSH ingress
rule. Existing tools found the problem late, after reviewers were already overloaded.

How Terraform Guardrail helps: v1 rules detect public exposure, v2 turns the rules into
enterprise policy, and v5 turns findings into remediation actions.

Steps:

1. Install the tool:

   ```bash
   pip install terraform-guardrail
   ```

2. Scan locally:

   ```bash
   terraform-guardrail scan ./infra
   ```

3. Enforce in CI:

   ```bash
   terraform-guardrail evaluate ./infra --provider aws --fail-on high
   ```

4. Open the v2 Enterprise app and click `TG006` or `TG008` in the policy catalog to read and copy
   the rule metadata.

5. Open the v3-v5 Governance app and run the governance loop to generate suggested fixes and a
   PR dry run.

Outcome: Risky network and storage exposure is stopped before `terraform apply`.

## 3. The Enterprise With Different Standards in Every Business Unit

The challenge: Each business unit interpreted tagging, encryption, and network standards
differently. Central teams could not prove that critical applications inherited the same safety
floor.

How Terraform Guardrail helps: v2 baselines and group enforcement establish a shared enterprise
minimum. v3 policy packs make reusable baselines portable.

Steps:

1. Install:

   ```bash
   pip install terraform-guardrail
   ```

2. Create or install policy content:

   ```bash
   terraform-guardrail enterprise pack install pci-dss
   ```

3. Create an org baseline:

   ```bash
   terraform-guardrail enterprise baseline create --name org-baseline --approved
   ```

4. Bind baseline or policies to org, group, or repo:

   ```bash
   terraform-guardrail enterprise binding create --target-type group --target payments
   ```

5. Use the v1-v5 Full platform app **v2-v3 Enterprise** tab to demonstrate inherited controls.

Outcome: Teams keep autonomy, but the enterprise safety floor becomes consistent and auditable.

## 4. The Developer Who Needed Fixes, Not Just Findings

The challenge: Developers received long security reports but did not know what exact Terraform
changes were expected.

How Terraform Guardrail helps: v4 suggested fixes and explainability describe why a finding
matters. v5 remediation plans and patch bundles turn findings into reviewable next steps.

Steps:

1. Install:

   ```bash
   pip install terraform-guardrail
   ```

2. Evaluate:

   ```bash
   terraform-guardrail evaluate ./infra --provider aws --context environment=production
   ```

3. Explain:

   ```bash
   terraform-guardrail intelligence explain <result-id>
   ```

4. Create remediation:

   ```bash
   terraform-guardrail enterprise remediation create <result-id>
   terraform-guardrail enterprise remediation patch-bundle <plan-id>
   ```

5. Use the v3-v5 Governance app **v5 Autonomous** tab to inspect the patch preview and PR dry run.

Outcome: Developers get actionable remediation, not only policy failure messages.

## 5. The Cloud Center of Excellence That Needed Governance to Run Itself

The challenge: The CCoE had good policies, but enforcement depended on people remembering to run
tools and collect reports.

How Terraform Guardrail helps: v5 scheduled scans, evidence schedules, automation runner output,
health, and trends create a lightweight governance operating loop.

Steps:

1. Install:

   ```bash
   pip install terraform-guardrail
   ```

2. Register scheduled scans:

   ```bash
   terraform-guardrail enterprise schedule create --name prod --path ./infra
   ```

3. Register evidence schedules:

   ```bash
   terraform-guardrail evidence schedule create --name monthly --format json
   ```

4. Run the automation cycle:

   ```bash
   terraform-guardrail enterprise automation run
   ```

5. Use the v1-v5 Full platform app **Evidence + Health** tab to show health signals and trend
   coverage.

Outcome: Governance becomes a scheduled operating model rather than an ad hoc review task.

## 6. The Multi-Cloud Team That Needed One Rule Language for Intent

The challenge: AWS, Azure, and GCP teams had different resource names and tools, but the business
intent was the same: no public exposure, storage must be encrypted, and resources must be owned.

How Terraform Guardrail helps: v3 cross-provider invariants let platform teams express intent
once and evaluate it across providers.

Steps:

1. Install:

   ```bash
   pip install terraform-guardrail
   ```

2. Run against a Terraform folder:

   ```bash
   terraform-guardrail evaluate ./infra --provider aws
   terraform-guardrail evaluate ./infra --provider azure
   ```

3. Watch for invariant rules:

   - `TG021`: public exposure invariant
   - `TG022`: storage encryption invariant
   - `TG023`: ownership tag invariant

4. Use the v3-v5 Governance app **v3 Ecosystem** tab to demonstrate policy packs and cross-team
   distribution.

Outcome: Teams keep provider-specific implementation details while leadership gets one control
language for enterprise intent.

## 7. The Unexpected Benefit: Governance Becomes Product Telemetry

The opportunity: Most enterprises think of guardrails as blockers. The bigger advantage is that
Terraform Guardrail turns policy outcomes into product telemetry for platform leadership.

How Terraform Guardrail helps: The tool records evaluations, evidence, waivers, remediation,
patch bundles, PR dry runs, schedules, and trend data. This shows whether platform standards are
getting easier or harder for teams to follow.

Steps:

1. Install:

   ```bash
   pip install terraform-guardrail
   ```

2. Run evaluations across representative repositories.

3. Export evidence and create remediation plans.

4. Review health:

   ```bash
   terraform-guardrail enterprise health
   terraform-guardrail enterprise trends
   ```

5. Open the v1-v5 Full platform app and use **Evidence + Health** to show executives:

   - Which rules fire most often.
   - Which teams need enablement.
   - Whether evidence coverage is improving.
   - Whether remediation is becoming faster.

Outcome: Governance shifts from "who blocked my pipeline?" to "where should the platform team
invest next?"
