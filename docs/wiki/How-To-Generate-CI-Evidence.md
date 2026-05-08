# How To Generate CI Evidence

Use evidence export when a pipeline needs an audit artifact for SOC2, ISO, PCI, or internal
governance.

## CLI workflow

```bash
terraform-guardrail evaluate ./infra --provider aws --baseline org-baseline --format json
```

The evaluation returns a result ID. Export evidence from that result:

```bash
terraform-guardrail evidence export <result-id> --format json
```

CSV is also supported:

```bash
terraform-guardrail evidence export <result-id> --format csv
```

PDF evidence is available for audit review packets:

```bash
terraform-guardrail evidence export <result-id> --format pdf
```

## AWS CodeBuild

Use the repository example:

```text
examples/aws-codepipeline/buildspec.yml
```

The pipeline should keep both artifacts:

- `guardrail-report.json`
- `guardrail-evidence.json`
- Optional PDF evidence for audit packets

## What the evidence contains

Evidence records include the evaluation decision, resolved policy IDs, finding details, timestamps,
and metadata such as owner, standard, control ID, and remediation when available.
