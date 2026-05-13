# Packaging & Installers

Terraform Guardrail Multi-Cloud Policy (MCP) (TerraGuard) generates packaging artifacts on release tags:

- Homebrew formula
- Linux install script (`curl | bash`)
- PyPI package for Windows, macOS, and Linux

These are published as GitHub Release assets. Publishing workflows will push Homebrew when the
required secrets are configured:

- `HOMEBREW_TAP_REPO` (for example `Huzefaaa2/homebrew-tap`)
- `HOMEBREW_TAP_TOKEN`

## Homebrew (macOS)

Release asset: [terraform-guardrail.rb](https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/terraform-guardrail.rb)

Once the tap is published:

```bash
brew install Huzefaaa2/tap/terraform-guardrail
```

## Windows

Install from PyPI with Python:

```powershell
py -m pip install terraform-guardrail
```

If `py` is not available, use the Python executable directly:

```powershell
python -m pip install terraform-guardrail
```

## Linux

Release asset: [install.sh](https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/install.sh)

```bash
curl -sSL https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/install.sh | bash
```
