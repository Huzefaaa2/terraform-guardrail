# Comparison with Other Tools

Terraform Guardrail MCP takes a fundamentally different approach to IaC governance than traditional
scanning or linting tools. Guardrail is delivered as a Model Context Protocol (MCP) server with a
CLI and web UI. It runs outside Terraform, exposing provider metadata, scanning configs and state
for sensitive values, and producing human-readable reports. Its rules engine focuses on secret
hygiene and write-only arguments and lets platform teams publish non-negotiable guardrails while
product teams compose contextual constraints.

By contrast, existing tools such as Checkov, TFLint and OPA/Conftest operate mainly as static code
analyzers embedded in CI pipelines. They scan Terraform files or plans for misconfigurations but do
not provide a centralized control plane or cross-provider context. The table below summarizes the
key differences:

| Category | Guardrail MCP | Checkov | TFLint | OPA/Conftest |
| --- | --- | --- | --- | --- |
| Primary purpose | External IaC governance control plane | Static multi-IaC security scanner | Terraform linter | General policy engine (Rego) |
| IaC support | Terraform + multi-cloud providers (AWS, Azure, GCP, Kubernetes, Helm, OCI, Vault, vSphere, Alicloud) | Terraform, CloudFormation, Kubernetes, Helm, ARM, Serverless | Terraform (HCL) | Any domain via Rego policies |
| Policy model | Central guardrail registry; platform invariants + product constraints; versioned and auditable | Built-in rules (Python/Rego) + custom policies | Provider-specific rule plugins; experimental Rego plugin | Rego rules only |
| Enforcement stage | Pre-apply; prevents bad state and drift; uses provider schemas | Pre-apply scan of templates and plans | Pre-apply linting for errors and best-practice drifts | Pre-apply checks (via Conftest) – outcome depends on integration |
| Governance & audit | Org-level guardrail registry, ownership boundaries, audit trail | No policy lifecycle management | No policy registry | No governance features |
| Developer experience | CLI/Server/Web UI; human-readable reports & fix suggestions | CLI with JSON/SARIF/JUnit output and graph insights | CLI with JSON/SARIF/JUnit output; configurable warnings | CLI library; steep learning curve |

## Why Guardrail complements scanners

Checkov provides a vast policy library and graph-based resource analysis to catch misconfigurations
early, and TFLint offers pluggable, provider-aware linting rules to detect invalid types, deprecated
syntax and best-practice drifts. These tools remain valuable for static analysis of Terraform code.
Guardrail MCP builds upon them by acting as a higher-order control plane: it uses provider metadata
to validate schema usage, prevents secret leakage and drift before Terraform mutates state, and
separates platform-owned safety floors from product-level constraints. In practice, teams often run
TFLint or Checkov in their CI to catch coding errors while Guardrail serves as the last line of
defense to enforce organizational guardrails and deliver contextual guidance.
