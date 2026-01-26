# Azure DevOps Marketplace Extension

This folder contains a scaffold for publishing a Terraform Guardrail task to the Azure DevOps
Marketplace.

## Build the extension

```bash
cd azure-devops-extension/tasks/terraform-guardrail
npm install
cd ../../
```

```bash
npm install -g tfx-cli
tfx extension create --manifest-globs vss-extension.json
```

## Publish

```bash
tfx extension publish --manifest-globs vss-extension.json --token <ADO_PAT>
```

Update `publisher` and `version` in `vss-extension.json` before publishing.

## GitHub Actions automation

Set these secrets to enable tag-based publishing:

- `ADO_PUBLISHER`
- `ADO_EXT_PAT`
