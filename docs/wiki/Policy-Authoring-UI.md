# Policy Authoring UI

The FastAPI web UI includes an enterprise workspace for policy authoring and review.

## Capabilities

- Create enterprise policies with owner, standard, control ID, description, and remediation.
- Auto-assign the next non-conflicting enterprise rule ID after the built-in `TG001`-`TG020`
  catalog.
- Edit policy details.
- Preview a selected policy against uploaded Terraform files before approval.
- Approve policies.
- Browse default rules and enterprise policies from the right-side catalog.
- Create org, group, and repo bindings for enforcement.
- Open task-first wiki guides from the top-right How-To Guides panel.

## Example

Create a policy named `Production S3 encryption` with:

- Owner: `platform-security`
- Standard: `SOC2`
- Control ID: `CC6.6`
- Remediation: `Enable default SSE with KMS`

The UI assigns the next available rule ID, such as `TG021`.

## Preview before approval

1. Select an enterprise policy from the right-side policy list.
2. In **Validate this policy before approval**, upload a Terraform folder or multiple files.
3. Click **Preview Policy**.
4. Review findings filtered to that policy rule ID.
5. Approve the policy only after the preview matches the expected behavior.

## API preview

```http
POST /policies/{policy_id}/preview
```

Example:

```json
{
  "path": "./infra",
  "actor": "security"
}
```

## Status

Implemented foundation with preview.
