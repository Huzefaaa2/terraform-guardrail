# Policy Metadata + Rich Failure Messages

Enterprise policies can add ownership, compliance, risk, expiry, and remediation context to scan
findings.

## Metadata fields

- Owner
- Standard
- Control ID
- Risk
- Expiry
- Remediation

## Default rule metadata

Built-in rules `TG001` through `TG020` include default risk and remediation guidance. When an
enterprise policy maps to a default rule ID, enterprise metadata is attached to matching findings
during evaluation.

## Example

Policy metadata:

```json
{
  "rule_id": "TG011",
  "metadata": {
    "owner": "platform-security",
    "standard": "SOC2",
    "control_id": "CC6.6",
    "risk": "medium",
    "remediation": "Enable default SSE with KMS."
  }
}
```

Enriched finding fields:

```json
{
  "rule_id": "TG011",
  "owner": "platform-security",
  "standard": "SOC2",
  "control_id": "CC6.6",
  "risk": "medium",
  "remediation": "Enable default SSE with KMS."
}
```

## Status

Implemented foundation: metadata model, default rule guidance, enriched evaluation findings, and
evidence export fields.
