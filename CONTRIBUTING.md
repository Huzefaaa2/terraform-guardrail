# Contributing

Thanks for your interest in Terraform-Guardrail!

## Contributor License Agreement (CLA)

All contributors must sign the Contributor License Agreement (CLA)
before their pull requests can be merged.

The CLA ensures that:
- Contributions can be legally redistributed
- The project remains sustainable
- Commercial and open-source usage remains clear

The CLA is required only once. You will be prompted automatically
when opening a pull request. By submitting a pull request, you agree
to the terms in `CLA.md`.

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
