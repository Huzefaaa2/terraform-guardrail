# Contributing

Thanks for your interest in Terraform-Guardrail!

## Contributor License Agreement (CLA)

All contributions require acceptance of the CLA. By submitting a pull
request, you agree to the terms in `CLA.md`.

## How to contribute

1. Fork the repository and create a feature branch.
2. Make changes with tests where applicable.
3. Run the test suite and linting.
4. Open a pull request.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
ruff check .
pytest
```
