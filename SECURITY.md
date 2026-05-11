# Security Policy

Terraform Guardrail is an IaC governance and policy evaluation tool. Please report security issues
privately before opening public issues.

## Supported Versions

Security fixes target the latest released major version and the active development branch.

## Reporting a Vulnerability

Send a private report to the repository owner through GitHub security advisories when available, or
contact the maintainer listed in the README.

Include:

- Affected version or commit.
- Reproduction steps.
- Impact assessment.
- Any logs or sample Terraform files needed to validate the issue.

## Scope

Examples of in-scope issues:

- Unsafe handling of Terraform state or secrets.
- Evidence export exposure risks.
- API behavior that leaks sensitive data.
- Supply-chain issues in packaging, CI, or examples.

Do not include real production secrets, customer data, or credentials in reports.
