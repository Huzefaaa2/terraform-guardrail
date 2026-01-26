# Policy Layering Model

Policy layering lets you apply guardrails in a predictable order:

1. **Base**: platform invariants.
2. **Env**: environment constraints (dev/stage/prod).
3. **App**: application-specific policies.

## CLI usage

```bash
terraform-guardrail scan infra \
  --policy-base baseline \
  --policy-env prod \
  --policy-app payments
```

## API usage

```json
{
  "path": "infra",
  "policy_base": "baseline",
  "policy_env": "prod",
  "policy_app": "payments"
}
```

## Environment variables

- `GUARDRAIL_POLICY_BASE`
- `GUARDRAIL_POLICY_ENV`
- `GUARDRAIL_POLICY_APP`

## Status

Delivered.
