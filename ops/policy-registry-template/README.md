# Policy Registry Template (Private Bundles)

Use this template to host private OPA bundles for Terraform-Guardrail.

## Structure

```
policy-registry-template/
  registry.json
  bundles/
  keys/
```

- `registry.json` indexes your bundles.
- `bundles/` holds `.tar.gz` bundle artifacts.
- `keys/` holds public keys for signed bundles.

## Quickstart (local)

```bash
cd ops/policy-registry-template
python -m http.server 8081
```

Then point Guardrail at the registry:

```bash
terraform-guardrail scan ./infra \
  --policy-bundle my-baseline \
  --policy-registry http://localhost:8081
```

## Bundle publishing checklist

1. Build a bundle
   ```bash
   opa build --bundle ./my-bundle --output bundles/my-baseline.tar.gz
   ```
2. Update `registry.json` with the new bundle ID and SHA256.
3. (Optional) Add public keys under `keys/` and reference `public_key_url`.

## Notes

- This is a static registry; you can host it with Nginx, S3, or any static site.
- Use signed bundles in production for verification.
