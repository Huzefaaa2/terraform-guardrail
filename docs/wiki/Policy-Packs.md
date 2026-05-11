# Policy Packs

Enterprise policy packs are curated policy metadata bundles that turn built-in TerraGuard rules
into installable baselines for common operating models.

## Delivered in v3.0 Ecosystem

- Built-in pack catalog.
- CLI commands to list, inspect, and install packs.
- REST API endpoints to list, inspect, and install packs.
- Automatic policy creation with metadata, owners, standards, control IDs, risk, and remediation.
- Optional baseline creation for each installed pack.
- Audit event recording for pack installation.

## Built-In Packs

| Pack ID | Purpose | Providers | Standards |
| --- | --- | --- | --- |
| `pci-dss` | Payment workload baseline | AWS, Azure, GCP | PCI DSS |
| `aws-control-tower` | AWS landing-zone controls | AWS | AWS Control Tower, AWS Well-Architected |
| `azure-landing-zone` | Azure landing-zone controls | Azure | Azure CAF, ISO 27001 |
| `banking-resiliency` | Financial-services resiliency baseline | AWS, Azure, GCP | Internal Banking Standard, SOC2 |

## CLI

List available packs:

```bash
terraform-guardrail enterprise pack list
```

Inspect a pack:

```bash
terraform-guardrail enterprise pack show pci-dss
```

Install a pack into the JSON enterprise store:

```bash
terraform-guardrail enterprise pack install pci-dss --actor platform-security
```

The install command creates approved enterprise policies and an approved baseline unless you pass
`--no-approve` or `--no-baseline`.

## REST API

List available packs:

```http
GET /packs
```

Show a pack:

```http
GET /packs/pci-dss
```

Install a pack:

```http
POST /packs/pci-dss/install
```

Example request:

```json
{
  "actor": "platform-security",
  "approve": true,
  "create_baseline": true
}
```

Example response:

```json
{
  "pack_id": "pci-dss",
  "pack_name": "PCI DSS Cloud Controls",
  "version": "0.1.0",
  "policy_ids": ["pol_..."],
  "baseline_id": "base_..."
}
```

## Status

Delivered as the first v3.0 Ecosystem capability.
