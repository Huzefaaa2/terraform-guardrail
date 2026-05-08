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
- Chocolatey release bump after local verification.

## Changed
- Version updated to 1.0.5 for republish.
- Chocolatey local verification guidance refreshed.
