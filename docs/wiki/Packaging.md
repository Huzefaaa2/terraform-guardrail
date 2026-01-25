# Packaging & Installers

Terraform Guardrail MCP generates packaging artifacts on release tags:

- Homebrew formula
- Chocolatey nuspec
- Linux install script (`curl | bash`)

These are published as GitHub Release assets.

## Homebrew (macOS)

Release asset: `terraform-guardrail.rb`

Future: publish a Homebrew tap for `brew install terraform-guardrail`.

## Chocolatey (Windows)

Release assets:

- `terraform-guardrail.nuspec`
- `chocolateyinstall.ps1`

Future: publish to Chocolatey for `choco install terraform-guardrail`.

## Linux

Release asset: `install.sh`

```bash
curl -sSL https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/install.sh | bash
```
