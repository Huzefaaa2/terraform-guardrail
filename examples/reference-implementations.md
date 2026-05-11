# v3 Reference Implementations

These examples show the v3 Guardrails-as-a-Service contract across common delivery tools.

| Tool | Example | Contract |
| --- | --- | --- |
| GitHub Actions | `github-actions/guardrails-service-v3.yml` | Starts API locally, calls `POST /service/evaluate`, uploads evidence |
| GitLab CI | `gitlab-ci/service-v3.gitlab-ci.yml` | Starts API locally, calls `POST /service/evaluate`, stores artifacts |
| Azure DevOps | `azure-devops/service-v3.yml` | Starts API locally, calls `POST /service/evaluate`, publishes artifacts |
| AWS CodePipeline | `aws-codepipeline/buildspec-service-v3.yml` | CodeBuild guardrail stage with service evaluation and evidence |

Each reference implementation uses:

- `policy_pack=aws-control-tower`
- caller-specific `request_id`
- JSON evidence export
- pass/warn/block enforcement
- persisted service response artifacts

The examples run the service API locally for portability. Enterprise deployments can point
`GUARDRAIL_API_URL` at a centrally hosted TerraGuard service.
