# How To Run a Drift Gate Before Apply

Use a drift gate when a pipeline must compare the current Terraform findings with an approved
snapshot before `terraform apply`.

## First Run

The first run creates the approved snapshot for the selected `snapshot_id`.

```bash
terraform-guardrail enterprise drift-gate ./infra \
  --provider aws \
  --baseline org-baseline \
  --snapshot-id prod \
  --evidence-format pdf \
  --format json
```

Expected result:

- `status` is `baseline_created`.
- Decision is `pass` or `warn` depending on findings.
- Evidence is written when `--evidence-format` is set.

## Later Runs

Run the same command in CI before apply. Terraform Guardrail compares the current findings to the
stored snapshot.

```bash
terraform-guardrail enterprise drift-gate ./infra \
  --provider aws \
  --baseline org-baseline \
  --snapshot-id prod \
  --format json
```

If findings are added or removed, the gate returns `block`, includes `drift_changed` in the
reasons, and exits non-zero for CI.

## Strict Mode

Use strict mode when CI must fail if the snapshot does not already exist.

```bash
terraform-guardrail enterprise drift-gate ./infra \
  --snapshot-id prod \
  --no-create-snapshot
```

## AWS CodeBuild

Use this in the Guardrail stage before the apply stage:

```bash
terraform-guardrail enterprise drift-gate . \
  --provider aws \
  --baseline org-baseline \
  --snapshot-id prod \
  --evidence-format json \
  --format json
```

See [AWS CodePipeline](AWS-CodePipeline) for the full CodeBuild pattern.
