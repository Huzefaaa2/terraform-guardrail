# Azure DevOps / Pipeline Extension

Terraform Guardrail MCP (TerraGuard) ships with an Azure DevOps pipeline template to run
pre-apply scans inside ADO pipelines.

## Template location

`/.azure/terraform-guardrail.yml`

## Usage

```yaml
trigger:
  - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - template: .azure/terraform-guardrail.yml
    parameters:
      path: "infra"
      failOn: "high"
      policyBundle: "baseline-signed"
      policyRegistry: "http://localhost:8081"
```

## Reports

The template generates and publishes JSON, SARIF, and JUnit outputs.

## Parameters

- `path`: path to scan (default `.`)
- `state`: optional `.tfstate` path
- `schema`: enable schema validation
- `failOn`: severity threshold (`low`, `medium`, `high`)
- `policyBundle`: bundle ID
- `policyRegistry`: registry URL
- `policyQuery`: OPA query override
- `jsonReport`, `sarifReport`, `junitReport`: report filenames
- `publishReports`: set to `false` to skip publish tasks
