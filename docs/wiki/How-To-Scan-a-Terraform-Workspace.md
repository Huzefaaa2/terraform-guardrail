# How To Scan a Terraform Workspace

This guide shows how to scan one file, many files, or a Terraform folder before infrastructure is
applied.

## Web UI

1. Open the Terraform Guardrail web UI.
2. In **Upload Terraform workspace**, choose a folder or select multiple `.tf`, `.tfvars`, and
   `.hcl` files.
3. Click **Scan Workspace**.
4. Review the scan report for high, medium, and low findings.
5. Click a rule ID in the right-side catalog to understand the rule.

## CLI

```bash
terraform-guardrail scan ./infra
```

Use JSON output when another tool needs to consume the report:

```bash
terraform-guardrail scan ./infra --format json
```

## Good first test

Try scanning a small folder that contains one Terraform file with an S3 bucket or security group.
This makes it easy to connect each finding to the resource that triggered it.
