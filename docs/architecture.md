# Architecture

Terraform Guardrail MCP is split into three layers:

1. **Compliance engine** (`src/terraform_guardrail/scanner`)
   - Parses Terraform configs and state files.
   - Applies rules around ephemeral values and secret hygiene.
2. **Interfaces**
   - CLI (`terraform_guardrail/cli/app.py`)
   - MCP server (`terraform_guardrail/mcp/server.py`)
   - Web UI (`terraform_guardrail/web/app.py`)
3. **Registry integration** (`terraform_guardrail/registry_client.py`)
   - Pulls provider metadata for AWS and Azure from Terraform Registry.

The goal is to keep the compliance engine standalone so it can be called by all interfaces.
