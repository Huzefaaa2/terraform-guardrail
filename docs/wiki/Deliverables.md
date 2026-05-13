# Deliverables Reference

This page explains each roadmap deliverable and points to the most relevant documentation.

<a name="dockerized-mcp-rest-api"></a>
## Dockerized Multi-Cloud Policy (MCP) + REST API

Container images for the Multi-Cloud Policy (MCP) server and REST API for consistent CI/CD usage.
See [Architecture](Architecture.md) and [Docker Compose](Docker-Compose.md).

<a name="cli-first-install"></a>
## CLI-first install

Package-first installs for local validation across platforms. See [Packaging](Packaging.md).

<a name="docker-compose-stack"></a>
## Docker Compose local stack (API + UI + registry)

Local stack for API, UI, and policy registry. See [Docker Compose](Docker-Compose.md).

<a name="github-action"></a>
## GitHub Action pre-apply / PR checks

Composite action for PR validation. See [GitHub Action](GitHub-Action.md).

<a name="gitlab-ci-templates"></a>
## GitLab CI templates

Shared template for GitLab pipelines. See [GitLab CI Templates](GitLab-CI.md).

<a name="azure-devops-extension"></a>
## Azure DevOps / Pipeline extension

Planned Azure DevOps extension for pre-apply checks in ADO pipelines.

## AWS CodePipeline + CodeBuild integration

Delivered buildspec integration for policy gates and evidence artifacts in AWS CodePipeline. See
[AWS CodePipeline](AWS-CodePipeline.md).

<a name="policy-authoring-ui"></a>
## Policy authoring UI

Delivered enterprise authoring workflow in the FastAPI web UI for creating, editing, approving,
previewing, and browsing policies. See [Policy Authoring UI](Policy-Authoring-UI.md).

<a name="policy-layering-model"></a>
## Policy layering model (base → env → app)

Layered policies for platform invariants (base), environment constraints, and app policies. See
[Policy Layering](Policy-Layering.md).

<a name="central-guardrail-registry"></a>
## Central guardrail registry

Registry service for policy bundles and audit history. See [Docker Compose](Docker-Compose.md).

<a name="policy-versioning-audit"></a>
## Policy versioning + audit trail

Versioned bundles with audit endpoints. See [Docker Compose](Docker-Compose.md).

<a name="registry-service-image"></a>
## Registry service image (GHCR)

Registry container published alongside core image. See [Packaging](Packaging.md).

<a name="homebrew-package"></a>
## Homebrew package (macOS)

Homebrew formula for macOS installs. See [Packaging](Packaging.md).

<a name="chocolatey-package"></a>
## Chocolatey package (Windows)

Chocolatey package for Windows installs. See [Packaging](Packaging.md).

<a name="linux-install-script"></a>
## Linux install script (curl | bash)

Linux one-liner install script. See [Packaging](Packaging.md).

<a name="policy-metadata-rich-messages"></a>
## Policy metadata + rich failure messages

Delivered metadata fields for ownership, compliance standards, control IDs, risk, expiry, and
remediation guidance. See [Policy Metadata](Policy-Metadata.md).

<a name="drift-prevention"></a>
## Drift-prevention rules before apply

Delivered drift checks and drift gates that compare current findings with an approved snapshot
before Terraform mutates state. See [Drift Prevention](Drift-Prevention.md).

<a name="org-wide-baselines"></a>
## Org-wide baselines

Delivered baseline lifecycle, versioning, approvals, and resolution order for baseline, pack/layer,
environment, and app scopes. See [Org-Wide Baselines](Org-Wide-Baselines.md).

<a name="group-level-enforcement"></a>
## Group-level enforcement

Delivered org, group, and repo bindings with inheritance-aware resolution. See
[Group-Level Enforcement](Group-Level-Enforcement.md).

<a name="evidence-export"></a>
## Evidence export (SOC2 / ISO / PCI)

Delivered JSON, CSV, and PDF evidence export records tied to evaluation results. See
[Evidence Export](Evidence-Export.md).

<a name="contributor-governance"></a>
## Contributor governance + public roadmap

Planned governance updates. See [Release Process](Release-Process.md).

<a name="reference-implementations"></a>
## Reference implementations across tools

Planned reference integrations across CI/CD tools and clouds.

<a name="cross-provider-invariants"></a>
## Cross-provider invariant enforcement

Planned cross-provider guardrails for consistent controls.

<a name="context-aware-evaluation"></a>
## Context-aware evaluation

Delivered in v4.0 development. Evaluation now resolves risk profiles from environment and risk
tier context, adjusts severity where the profile is stricter, and records the matched profile plus
adjustments in result metadata.

<a name="suggested-fixes"></a>
## Suggested fixes + recommendations

Delivered in v4.0 development. Findings now include concrete `suggested_fix` guidance and the
recommendation catalog is available through CLI and API surfaces.

<a name="explainability-reports"></a>
## Explainability reports

Delivered in v4.0 development. Evaluation results can now be explained through CLI and API,
including decision reasons, applied policies, baseline context, risk profile adjustments, finding
explanations, and next actions.

<a name="enterprise-sarif-junit"></a>
## Enterprise SARIF/JUnit bridge

Delivered in v4.0 development. Stored enterprise evaluations can now render SARIF and JUnit XML
reports through CLI and API, and the reference CI templates publish those artifacts.

<a name="policy-waivers"></a>
## Policy waivers and exceptions

Delivered in v4.0 development. Teams can request, approve, and revoke time-bound policy waivers
with owner, reason, expiry, optional path/target scope, audit trail, explainability metadata, and
decision suppression for active approved waivers.
