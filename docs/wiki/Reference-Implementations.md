# Reference Implementations

Reference implementations show how to run TerraGuard v3 across common delivery tools using the
Guardrails-as-a-Service API and v3 policy packs.

## Delivered in v3.0 Development

| Tool | Example | Purpose |
| --- | --- | --- |
| GitHub Actions | [`examples/github-actions/guardrails-service-v3.yml`](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/examples/github-actions/guardrails-service-v3.yml) | PR gate with service evaluation and evidence upload |
| GitLab CI | [`examples/gitlab-ci/service-v3.gitlab-ci.yml`](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/examples/gitlab-ci/service-v3.gitlab-ci.yml) | Pipeline gate with service evaluation artifacts |
| Azure DevOps | [`examples/azure-devops/service-v3.yml`](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/examples/azure-devops/service-v3.yml) | Pipeline task sequence with service evaluation and published artifacts |
| AWS CodePipeline | [`examples/aws-codepipeline/buildspec-service-v3.yml`](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/examples/aws-codepipeline/buildspec-service-v3.yml) | CodeBuild guardrail stage using the v3 service contract |

## Common Pattern

Each reference implementation:

1. Installs Terraform Guardrail.
2. Starts the API locally for the pipeline job.
3. Calls `POST /service/evaluate`.
4. Uses a CI-native `request_id`.
5. Evaluates with `policy_pack=aws-control-tower`.
6. Stores `guardrail-service-response.json` and generated evidence.
7. Fails the job when the decision is `block`.

For centrally hosted deployments, replace `GUARDRAIL_API_URL` with your TerraGuard service URL and
remove the local API startup step.

## Status

Delivered as the fourth v3.0 Ecosystem capability.
