# Roadmap (Major Releases)

Minor releases deliver increments within each major deliverable. Major releases group outcomes by
phase.

Latest delivered major release: [v5.0.0 Autonomous Governance Release](Release-v5.0.0).
Current release-hardening track: v5.0.0 package verification, final documentation, and publishing.

Legend: <span style="color: green">✅ Delivered</span> • <span style="color: orange">🚧 Planned</span>

| Deliverable | v1.0 Foundation | v2.0 Enterprise | v3.0 Ecosystem | v4.0 Intelligent | Docs |
| --- | --- | --- | --- | --- | --- |
| Dockerized Multi-Cloud Policy (MCP) + REST API | <span style="color: green">✅ Delivered (0.2.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/REST-API) |
| CLI-first install | <span style="color: green">✅ Delivered (0.2.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Packaging) |
| Docker Compose local stack (API + UI + registry) | <span style="color: green">✅ Delivered (0.2.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Docker-Compose) |
| GitHub Action pre-apply / PR checks | <span style="color: green">✅ Delivered (0.2.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/GitHub-Action) |
| Central guardrail registry | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Registry) |
| Policy versioning + audit trail | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Registry) |
| Registry service image (GHCR) | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Packaging) |
| Homebrew package (macOS) | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Packaging) |
| Windows install via PyPI | <span style="color: green">✅ Delivered (0.2.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Packaging) |
| Linux install script (curl \| bash) | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Packaging) |
| GitLab CI templates | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/GitLab-CI) |
| Azure DevOps / Pipeline extension | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Azure-DevOps) |
| Policy layering model (base → env → app) | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Layering) |
| Custom rules (Option A/B + local bundles) | <span style="color: green">✅ Delivered (1.0.x)</span> |  |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Custom-Rules) |
| AWS CodePipeline + CodeBuild integration |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/AWS-CodePipeline) |
| Policy authoring UI |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Authoring-UI) |
| Policy metadata + rich failure messages |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Metadata) |
| Drift-prevention rules before apply |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Drift-Prevention) |
| Org-wide baselines |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Org-Wide-Baselines) |
| Group-level enforcement |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Group-Level-Enforcement) |
| Evidence export (SOC2 / ISO / PCI) |  | <span style="color: green">✅ Delivered (2.0.0)</span> |  |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Evidence-Export) |
| Contributor governance + public roadmap |  |  | <span style="color: green">✅ Delivered (v3.0 development)</span> |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Governance) |
| Reference implementations across tools |  |  | <span style="color: green">✅ Delivered (v3.0 development)</span> |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Reference-Implementations) |
| Cross-provider invariant enforcement |  |  | <span style="color: green">✅ Delivered (v3.0 development)</span> |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Cross-Provider-Invariants) |
| Guardrails-as-a-Service API |  |  | <span style="color: green">✅ Delivered (v3.0 development)</span> |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Guardrails-as-a-Service) |
| Enterprise policy packs |  |  | <span style="color: green">✅ Delivered (v3.0 development)</span> |  | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Packs) |
| Context-aware evaluation |  |  |  | <span style="color: green">✅ Delivered (v4.0 development)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Context-Aware-Evaluation) |
| Suggested fixes + recommendations |  |  |  | <span style="color: green">✅ Delivered (v4.0 development)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Suggested-Fixes) |
| Explainability reports + CI comment output |  |  |  | <span style="color: green">✅ Delivered (v4.0 development)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Explainability-Reports) |
| Enterprise SARIF/JUnit bridge |  |  |  | <span style="color: green">✅ Delivered (v4.0 development)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Enterprise-SARIF-JUnit) |
| Policy waivers and exceptions |  |  |  | <span style="color: green">✅ Delivered (v4.0 development)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Policy-Waivers) |

## v5.0 Autonomous Governance

| Deliverable | Status | Docs |
| --- | --- | --- |
| Remediation plans + PR-ready fix guidance | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Governance health reporting | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Scheduled governance scan configuration | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Scheduled multi-repo background runner | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Remediation patch bundle scaffold | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| GitHub pull request automation | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Evidence scheduling | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Background runner scaffold | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
| Governance trend dashboard | <span style="color: green">✅ Delivered (v5.0 foundation)</span> | [Docs](https://github.com/Huzefaaa2/terraform-guardrail/wiki/Autonomous-Governance) |
