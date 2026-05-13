# Policy Waivers

Policy waivers provide an auditable exception workflow for v4 intelligent evaluations. They are
designed for temporary, owner-backed exceptions rather than permanent policy bypasses.

## Status

Delivered in v4.0 development.

## What It Does

- Creates requested waivers with rule ID, owner, reason, expiry, and optional path or target.
- Requires approval before a waiver affects evaluation decisions.
- Annotates waived findings with `waiver_id` and `waiver_expires_at`.
- Keeps waived findings visible in JSON, SARIF, JUnit, explainability reports, and Markdown
  comments.
- Ignores active approved waivers when deciding `pass`, `warn`, or `block`.
- Writes audit events for request, approval, revocation, and updates.

## CLI

Request a waiver:

```bash
terraform-guardrail enterprise waiver create \
  --rule-id TG011 \
  --reason "Legacy module migration" \
  --owner platform-security \
  --expires-at 2026-12-31T00:00:00Z
```

Approve it:

```bash
terraform-guardrail enterprise waiver approve <waiver-id> --actor security-reviewer
```

Create and approve in one command for demos or controlled automation:

```bash
terraform-guardrail enterprise waiver create \
  --rule-id TG011 \
  --reason "Approved migration window" \
  --owner platform-security \
  --expires-at 2026-12-31T00:00:00Z \
  --approve
```

List or revoke:

```bash
terraform-guardrail enterprise waiver list --status approved
terraform-guardrail enterprise waiver revoke <waiver-id> --actor security-reviewer
```

## API

```http
POST /waivers
GET /waivers
POST /waivers/{waiver_id}/approve
POST /waivers/{waiver_id}/revoke
```

Example request:

```json
{
  "rule_id": "TG011",
  "reason": "Legacy module migration",
  "owner": "platform-security",
  "expires_at": "2026-12-31T00:00:00Z",
  "requested_by": "app-team"
}
```

## Matching Rules

A waiver applies when:

- `status` is `approved`.
- `expires_at` is still in the future.
- `rule_id` matches the finding rule.
- Optional `path`, `policy_id`, and target context also match when provided.

## Evaluation Behavior

Waived findings remain visible but do not trigger a block or warning decision. Explainability
reports include the waiver ID and expiry so reviewers can see why the decision changed.

## Web UI and Streamlit

The FastAPI enterprise web UI includes a **Policy waivers** panel where users can request, approve,
and revoke waivers. Matching findings in the intelligent evaluation report display the waiver ID
and expiry.

The Streamlit enterprise demo includes a demo waiver selector in the evaluation context panel. It
creates an approved temporary waiver and shows the applied waiver table after evaluation.
