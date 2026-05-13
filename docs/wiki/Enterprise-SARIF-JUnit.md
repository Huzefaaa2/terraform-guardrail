# Enterprise SARIF and JUnit Reports

Enterprise SARIF and JUnit reports make v4 intelligent evaluations visible in CI-native dashboards.
They are generated from stored evaluation results, so the same context-aware findings, policy
metadata, remediation, and suggested fixes can be consumed by GitHub code scanning, GitLab test
reports, Azure DevOps test tabs, and artifact stores.

## Status

Delivered in v4.0 development.

## CLI

```bash
terraform-guardrail enterprise report <evaluation-result-id> \
  --format sarif \
  --output guardrail-report.sarif
```

```bash
terraform-guardrail enterprise report <evaluation-result-id> \
  --format junit \
  --output guardrail-report.junit.xml
```

## API

```http
GET /results/{result_id}/reports/sarif
GET /results/{result_id}/reports/junit
```

## CI Artifacts

The v3 service reference implementations now emit v4 native reports:

- `guardrail-report.sarif`
- `guardrail-report.junit.xml`
- `guardrail-comment.md`
- `guardrail-service-response.json`
- JSON evidence artifacts

## Behavior

- High-severity findings become SARIF `error` results and JUnit failures.
- Medium findings become SARIF `warning` results and JUnit passing test cases with guidance in
  `system-out`.
- Low findings become SARIF `note` results.
- Suggested fixes are included in SARIF result properties and JUnit failure/system output text.
