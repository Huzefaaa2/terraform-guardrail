# Baseline Guardrails

This baseline pack provides policy checks that mirror the built-in compliance rules. It is meant
as a starter pack for secrets hygiene, encryption, networking, and governance standards.

## Covered controls (sample)

- Secrets hygiene (ephemeral variables, no hardcoded secrets)
- Public exposure (S3 ACLs, security group ingress)
- Encryption defaults (S3, RDS, EBS)
- HTTP listeners on load balancers
- Mandatory tags for ownership and environment
- Region and instance-type constraints (driven by policy data)

Use the CLI to fetch bundles:

```bash
terraform-guardrail policy fetch baseline --destination ./policies
```

You can customize policy data (e.g., allowed regions) by editing `data.json` within the bundle
or by publishing your own bundle via the registry.
