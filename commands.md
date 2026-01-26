# Terraform-Guardrail CLI Commands

This page lists the CLI commands and common usage patterns.

## Global

```bash
terraform-guardrail --help
terraform-guardrail --version
```

## scan

Scan Terraform files, optional state, schema validation, and policy bundles.

```bash
terraform-guardrail scan PATH [OPTIONS]
```

Common options:
- `--state PATH` Optional `.tfstate` file
- `--format pretty|json`
- `--schema` Enable schema-aware validation
- `--policy-bundle ID` Evaluate a single policy bundle
- `--policy-layers ID --policy-layers ID ...` Ordered policy bundle layers
- `--policy-base ID --policy-env ID --policy-app ID` Convenience layering flags
- `--policy-registry URL` Registry base URL
- `--policy-query QUERY` OPA query override
- `--fail-on low|medium|high` Exit non-zero on severity threshold

Examples:
```bash
terraform-guardrail scan ./infra --schema
terraform-guardrail scan ./infra --state ./terraform.tfstate --format json
terraform-guardrail scan ./infra --policy-bundle baseline
terraform-guardrail scan ./infra --policy-base baseline --policy-env prod --policy-app payments
```

## generate

Generate a provider resource snippet.

```bash
terraform-guardrail generate PROVIDER RESOURCE [--name NAME]
```

Example:
```bash
terraform-guardrail generate aws aws_s3_bucket --name app_bucket
```

## mcp

Start the MCP server over stdio.

```bash
terraform-guardrail mcp
```

## web

Start the web UI.

```bash
terraform-guardrail web [--host HOST] [--port PORT]
```

## api

Start the REST API.

```bash
terraform-guardrail api [--host HOST] [--port PORT]
```

## registry-api

Start the policy registry API service.

```bash
terraform-guardrail registry-api [--host HOST] [--port PORT]
```

## policy

Policy registry commands.

```bash
terraform-guardrail policy list [--registry URL]
terraform-guardrail policy fetch BUNDLE_ID [--destination PATH] [--registry URL]
```

## rules

List built-in rule IDs and descriptions.

```bash
terraform-guardrail rules list
```
