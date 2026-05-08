# Group-Level Enforcement

Group-level enforcement lets platform teams bind approved enterprise policies or baselines to an
org, group, or repo. Evaluation resolves inherited bindings before returning a pass/warn/block
decision.

## Inheritance model

Resolution follows:

1. Explicit baseline passed to evaluation.
2. Approved org-wide baselines.
3. Direct org, group, or repo bindings.
4. Parent bindings declared on a repo or group binding.

This supports org → group → repo inheritance without requiring every repository to configure the
same policy list.

## API

```http
POST /bindings
GET /bindings?target_type=group&target=platform
POST /bindings/resolve
POST /integrations/gitlab/groups
GET /integrations/gitlab/groups/{group_id}/policies
```

Example binding:

```json
{
  "target_type": "group",
  "target": "platform",
  "policy_ids": ["pol_example"],
  "baseline_ids": ["base_example"],
  "parent": "acme"
}
```

## CLI

```bash
terraform-guardrail enterprise binding create \
  --target-type group \
  --target platform \
  --policy-id pol_example \
  --baseline-id base_example \
  --parent acme
```

```bash
terraform-guardrail enterprise binding list --target platform
```

Resolve effective policies after inheritance:

```bash
terraform-guardrail enterprise binding resolve --org acme --group platform --repo infra
```

The resolver returns:

- Binding targets that participated in inheritance
- Baseline IDs
- Policy IDs
- Full policy records

## Web UI

Use **Bind policies to orgs, groups, or repos** in the enterprise workspace to create bindings and
view current bindings. Use **Preview effective policies** to see exactly which policies apply to an
org, group, or repo before enabling a pipeline gate.

## Status

Implemented foundation: JSON-backed bindings, API, CLI, UI creation, audit events, inherited
evaluation resolution, and effective-policy preview.
