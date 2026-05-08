# How To Create an Enterprise Policy

Enterprise policies add ownership, compliance, and remediation context to the rule catalog.
In v2.0.0, policies can be created through the web UI, REST API, or CLI and persisted in the
enterprise JSON store.

## Example policy

| Field | Example |
| --- | --- |
| Policy name | Production S3 encryption |
| Owner | platform-security |
| Standard | SOC2 |
| Control ID | CC6.6 |
| Description | S3 buckets in production must use default encryption |
| Remediation | Enable default SSE with KMS |

The web UI assigns the next available rule ID automatically, such as `TG021`, so new enterprise
policies do not conflict with the built-in rule catalog.

## Web UI

1. Open **Create enterprise policy**.
2. Enter the policy name and metadata.
3. Leave the rule ID field as-is. It is auto-assigned.
4. Click **Create Policy**.
5. Select the policy from the right-side **Enterprise Policies** list.
6. Review or edit the details, then approve the policy when it is ready.

## CLI

```bash
terraform-guardrail enterprise policy create \
  --name "Production S3 encryption" \
  --owner platform-security \
  --standard SOC2 \
  --control-id CC6.6 \
  --description "S3 buckets in production must use default encryption" \
  --remediation "Enable default SSE with KMS"
```

Approve the policy when it is ready:

```bash
terraform-guardrail enterprise policy approve <policy-id> --actor platform-security
```

## Add to enforcement

Attach the approved policy to a baseline or binding:

```bash
terraform-guardrail enterprise baseline create \
  --name org-baseline \
  --policy-id <policy-id> \
  --approved
```

```bash
terraform-guardrail enterprise binding create \
  --target-type group \
  --target platform \
  --policy-id <policy-id>
```
