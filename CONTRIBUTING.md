# Contributing to Terraform Guardrail

Terraform Guardrail accepts contributions that improve IaC governance, policy evaluation,
integration examples, documentation, and test coverage.

## Contribution Flow

1. Open an issue first for features, behavior changes, or roadmap items.
2. Keep pull requests focused on one capability or fix.
3. Add or update tests for behavior changes.
4. Update README/wiki docs when a user-facing workflow changes.
5. Sign the CLA when the bot asks.

## Local Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap Labels

Use these labels when opening issues:

- `v3-ecosystem`: policy packs, service API, reference implementations, governance.
- `v4-intelligent`: context-aware evaluation and suggested fixes.
- `bug`: confirmed defect or regression.
- `docs`: README, wiki, or example updates.
- `integration`: CI/CD, cloud, package, or tool integrations.

## Pull Request Expectations

- Explain what changed and why.
- Include test output.
- Link the issue or roadmap item.
- Avoid unrelated formatting or refactors.
- Keep backwards compatibility unless the change is explicitly planned as breaking.

## Maintainer Review

Maintainers review for correctness, compatibility, tests, documentation, and operational risk.
Security-sensitive changes may require extra review before merge.
