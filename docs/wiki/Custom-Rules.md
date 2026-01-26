# Custom Rules

Terraform-Guardrail supports two customization paths:

- **Option A (built-in knobs):** quick, environment-driven policies.
- **Option B (OPA bundles):** full custom policy packs with versioning.

## Option A — Environment knobs (no code)

Use environment variables to enforce common standards:

```bash
export GUARDRAIL_REQUIRED_TAGS="owner,environment,cost_center"
export GUARDRAIL_ALLOWED_REGIONS="eastus,westus2"
export GUARDRAIL_BLOCKED_REGIONS="eastus2"
export GUARDRAIL_ALLOWED_INSTANCE_TYPES="t3.medium,t3.large"
export GUARDRAIL_ALLOWED_SKUS="Standard_D4s_v5,Standard_D8s_v5"

tfguardrail scan ./infra
```

These drive built-in rules:

- `TG016` Missing mandatory tags
- `TG017` Region/location not allowed
- `TG018` Instance type/SKU not allowed

## Option B — OPA bundles (recommended)

OPA bundles are the safest way to add or modify guardrails.

### 1) Scaffold a bundle

```bash
terraform-guardrail policy init --destination ./my-bundle --bundle-name guardrail
```

This creates:

```
my-bundle/
  .manifest
  data.json
  policies/guardrail.rego
```

### 2) Add a rule

Edit `policies/guardrail.rego` and add a deny rule. Example: restrict Azure regions.

```rego
import rego.v1

deny contains output if {
  block := resource_blocks[_]
  block.type == "azurerm_resource_group"
  allowed := data.guardrail.allowed_regions
  allowed
  value := block.attrs.location
  not value_in_list(value, allowed)

  output := {
    "message": sprintf("Disallowed Azure region %s", [value]),
    "severity": "medium",
    "rule_id": "CUSTOM002",
    "path": block.file.path,
  }
}
```

Set `data.json`:

```json
{
  "guardrail": {
    "allowed_regions": ["eastus", "westus2"]
  }
}
```

### 3) Build a bundle

```bash
opa build --bundle ./my-bundle --output my-bundle.tar.gz
```

### 4) Evaluate locally

```bash
terraform-guardrail scan ./infra --policy-bundle-path ./my-bundle.tar.gz
```

### 5) Publish to registry (optional)

Host your bundle and register it in `registry.json`, then run:

```bash
terraform-guardrail scan ./infra --policy-bundle my-bundle
```

## Notes

- `--policy-bundle-path` accepts a bundle directory or `.tar.gz` file.
- Use signed bundles for production.
- Keep custom rules in a separate repo for auditability.
