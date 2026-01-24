# Terraform Guardrail MCP Wiki

Welcome to the Terraform Guardrail MCP documentation. This wiki covers architecture, usage,
compliance rules, and deployment guides for the CLI, MCP server, and Streamlit UI.

## Quick links

- [Architecture](Architecture.md)
- [CLI Usage](CLI-Usage.md)
- [MCP Server](MCP-Server.md)
- [Compliance Rules](Compliance-Rules.md)
- [Streamlit Deployment](Streamlit-Deployment.md)
- [Live Streamlit App](https://terraform-guardrail.streamlit.app/)
- [PyPI Package](https://pypi.org/project/terraform-guardrail/)
- [Release Process](Release-Process.md)
- [Diagrams](Diagrams.md)
- Supported providers: AWS, Azure, GCP, Kubernetes, Helm, OCI, Vault, Alicloud, vSphere
 - Latest version: 0.2.7
 - Container image: https://github.com/Huzefaaa2/terraform-guardrail/pkgs/container/terraform-guardrail

## Feature Matrix

| Area | CLI | Web UI / Streamlit |
| --- | --- | --- |
| Config scan (`.tf`, `.tfvars`, `.hcl`) | Yes | Yes |
| State leak scan (`.tfstate`) | Yes | Yes |
| Schema-aware validation | Yes | Yes |
| CSV export | No | Yes |
| Provider metadata | Yes | Yes |
| Snippet generation | Yes | No |
| Multi-file scan | Yes (directory) | Yes (upload up to 10) |
