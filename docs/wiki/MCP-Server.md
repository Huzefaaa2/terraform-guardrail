# Multi-Cloud Policy (MCP) Server

Terraform Guardrail Multi-Cloud Policy (MCP) (TerraGuard) exposes tools for scan, metadata, and snippet generation via stdio.

## Start

```bash
terraform-guardrail mcp
```

## Tools

- `scan_terraform`: Run compliance checks over a path and optional state file.
- `get_provider_metadata`: Fetch provider metadata from Terraform Registry (AWS + Azure).
- `generate_snippet`: Generate Terraform snippets for common AWS/Azure resources.

## Example payload

```json
{"jsonrpc":"2.0","id":1,"method":"call_tool","params":{"name":"scan_terraform","arguments":{"path":"./examples"}}}
```
