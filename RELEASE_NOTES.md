# v5.0.0

## Highlights
- v5.0 Autonomous Governance foundation with remediation plans and governance health reporting.
- Remediation plans turn evaluation findings into reviewable actions with suggested fixes and Terraform snippet previews for common safe fixes.
- Governance health summarizes stored evaluations, decisions, recurring rules, waivers, evidence exports, and risk signals.
- Scheduled governance scan targets define path, cadence, context, baseline, and fail threshold, with manual execution records.
- Remediation patch bundles generate provider-neutral PR scaffolds from remediation plans.
- Evidence schedules define recurring audit exports by result, context, standard, or control.

## Added
- `terraform-guardrail enterprise remediation create/list/show` commands.
- `terraform-guardrail enterprise health` command.
- API endpoints for remediation plans and governance health.
- API and CLI support for scheduled scan targets and on-demand scheduled runs.
- API and CLI support for remediation patch bundle scaffolds.
- API and CLI support for evidence schedules and on-demand evidence schedule runs.

## Changed
- Version updated to 5.0.0 for the Autonomous Governance development track.

---

# v4.0.0

## Highlights
- v4.0 Intelligent release with context-aware evaluation, suggested fixes, explainability reports, SARIF/JUnit reporting, and policy waivers.
- Risk profiles let enterprise teams tune severity and fail-on behavior by environment and risk tier without changing Terraform code.
- Findings now carry practical suggested fixes and richer explanations so developers can understand what failed, why it failed, and what to do next.
- CI systems can publish Markdown decision comments, SARIF code scanning reports, and JUnit test reports from the same evaluation result.
- Policy waivers provide approved, expiring exceptions that remain visible in reports while being excluded from pass/warn/block decisions.

## Added
- `terraform-guardrail enterprise risk-profile list/show/create` commands.
- `terraform-guardrail enterprise recommendations` for rule-level suggested fixes.
- `terraform-guardrail enterprise explain` with `pretty`, `json`, and `markdown` output.
- `terraform-guardrail enterprise report` for SARIF and JUnit exports.
- `terraform-guardrail enterprise waiver create/list/approve/revoke` commands.
- API endpoints for risk profiles, recommendations, explainability, Markdown comments, SARIF/JUnit reports, and waiver lifecycle.
- Web UI and Streamlit Enterprise panels for context intelligence, suggested fixes, and waivers.

## Changed
- Version updated to 4.0.0 for the Intelligent release.
- README and wiki roadmap now mark v4.0 Intelligent roadmap items as delivered.
- v3 reference implementations now generate explainability comments, SARIF reports, and JUnit reports.

---

# v3.0.0

## Highlights
- v3.0 Ecosystem release with installable enterprise policy packs, a CI-friendly Guardrails-as-a-Service API, cross-provider invariant enforcement, and reference implementations across major delivery tools.
- Built-in policy packs for PCI DSS, AWS Control Tower, Azure landing zone, and banking resiliency baselines.
- `POST /service/evaluate` contract with caller request IDs, optional policy pack installation, evidence export, result links, and pass/warn/block decisions.
- New normalized invariant rules TG021-TG023 for public exposure, storage encryption, and ownership metadata across AWS, Azure, and GCP.
- End-to-end v3 examples for GitHub Actions, GitLab CI, Azure DevOps, and AWS CodePipeline/CodeBuild.
- Contributor governance package with contribution guide, security policy, code of conduct, issue templates, PR template, and public roadmap metadata.

## Added
- `terraform-guardrail enterprise pack list/show/install` commands.
- API endpoints: `GET /packs`, `GET /packs/{pack_id}`, `POST /packs/{pack_id}/install`, and `POST /service/evaluate`.
- Built-in `terraform_guardrail.policy_packs` catalog packaged with the Python distribution.
- Reference implementation files under `examples/*/*service-v3*`.
- Governance files and validation tests.

## Changed
- Version updated to 3.0.0 for the Ecosystem release.
- README and wiki roadmap now mark v3.0 Ecosystem roadmap items as delivered and identify v4.0 Intelligent as the next development track.

---

# v2.0.0

## Highlights
- Enterprise governance foundation with JSON-backed policy, baseline, binding, evaluation, audit, drift, and evidence stores.
- REST API and CLI support for enterprise policy lifecycle, org baselines, group enforcement, evaluation, drift gates, and evidence export.
- Web UI policy authoring with multi-file/folder Terraform uploads, default rule catalog browsing, enterprise policy preview, baseline management, enforcement preview, and how-to guide links.
- AWS CodePipeline/CodeBuild integration scaffold with guardrail buildspec generation and evidence artifacts.

## Added
- `terraform-guardrail evaluate` for pass/warn/block enterprise decisions.
- `terraform-guardrail enterprise policy`, `baseline`, `binding`, `drift-check`, `drift-gate`, and `aws codepipeline init` commands.
- `terraform-guardrail evidence export` for JSON, CSV, and PDF evidence records.
- API endpoints for policies, versions, approvals, baselines, bindings, evaluations, results, drift checks, drift gates, and exports.
- Rich finding metadata fields for owner, standard, control ID, risk, expiry, remediation, and evidence ID.
- Wiki how-to guides for scanning workspaces, creating enterprise policies, using default rules, and generating CI evidence.

## Changed
- Version updated to 2.0.0 for the Enterprise foundation release.
- README and wiki roadmap now mark v2.0 Enterprise roadmap items as delivered.

---

# v1.0.5

## Highlights
- Package release bump after local verification.

## Changed
- Version updated to 1.0.5 for republish.
- Local package verification guidance refreshed.
