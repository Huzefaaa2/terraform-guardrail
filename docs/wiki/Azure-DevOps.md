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

## Marketplace extension scaffold

The repository includes a Marketplace extension scaffold in `azure-devops-extension/` with a
`Terraform Guardrail Scan` task. Build it using `tfx`:

```bash
cd azure-devops-extension/tasks/terraform-guardrail
npm install
cd ../../

npm install -g tfx-cli
tfx extension create --manifest-globs vss-extension.json
tfx extension publish --manifest-globs vss-extension.json --token <ADO_PAT>
```

## Marketplace task usage

After publishing the extension, add the task by name in your pipeline:

```yaml
trigger:
  - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - task: TerraformGuardrail@1
    inputs:
      path: "infra"
      failOn: "high"
      policyBundle: "baseline-signed"
      policyRegistry: "http://localhost:8081"
      jsonReport: "guardrail-report.json"
      sarifReport: "guardrail-report.sarif"
      junitReport: "guardrail-report.junit.xml"

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: "JUnit"
      testResultsFiles: "guardrail-report.junit.xml"
      failTaskOnFailedTests: false

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: "guardrail-report.json"
      ArtifactName: "guardrail-json"
```

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
