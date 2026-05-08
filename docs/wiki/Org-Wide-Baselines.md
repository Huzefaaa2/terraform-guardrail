# Org-Wide Baselines

Org-wide baselines define the non-negotiable safety floor for all repositories and environments.
Approved org baselines are automatically considered during enterprise evaluation.

## Lifecycle

Baselines support:

- Creation with an initial policy set
- Version records
- Approval records
- Audit events
- Binding to org, group, or repo targets

## CLI

Create a baseline:

```bash
terraform-guardrail enterprise baseline create \
  --name org-baseline \
  --policy-id pol_example
```

Create a new version:

```bash
terraform-guardrail enterprise baseline version org-baseline \
  --version 1.0.0 \
  --policy-id pol_example
```

Approve the version:

```bash
terraform-guardrail enterprise baseline approve org-baseline --actor security
```

View lifecycle history:

```bash
terraform-guardrail enterprise baseline history org-baseline
```

## API

```http
POST /baselines
GET /baselines
POST /baselines/{baseline_id}/versions
GET /baselines/{baseline_id}/versions
POST /baselines/{baseline_id}/approve
GET /baselines/{baseline_id}/approvals
```

## Web UI

Use **Org-wide baseline lifecycle** in the enterprise workspace to create baselines, version them,
and approve them before binding to groups or repositories.

## Status

Implemented foundation: JSON-backed baseline lifecycle, versioning, approvals, audit events, API,
CLI, and UI controls.
