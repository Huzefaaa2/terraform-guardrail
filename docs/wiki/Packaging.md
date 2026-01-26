# Packaging & Installers

Terraform Guardrail MCP (TerraGuard) generates packaging artifacts on release tags:

- Homebrew formula
- Chocolatey nuspec
- Linux install script (`curl | bash`)

These are published as GitHub Release assets. Publishing workflows will push Homebrew and
Chocolatey when the required secrets are configured:

- `HOMEBREW_TAP_REPO` (for example `Huzefaaa2/homebrew-tap`)
- `HOMEBREW_TAP_TOKEN`
- `CHOCO_API_KEY`

## Homebrew (macOS)

Release asset: [terraform-guardrail.rb](https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/terraform-guardrail.rb)

Once the tap is published:

```bash
brew install Huzefaaa2/tap/terraform-guardrail
```

## Chocolatey (Windows)

Release assets:

- [terraform-guardrail.nuspec.in](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/packaging/chocolatey/terraform-guardrail.nuspec.in)
- [chocolateyinstall.ps1](https://github.com/Huzefaaa2/terraform-guardrail/blob/main/packaging/chocolatey/tools/chocolateyinstall.ps1)

Once published:

```powershell
choco install terraform-guardrail
```

## Linux

Release asset: [install.sh](https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/install.sh)

```bash
curl -sSL https://github.com/Huzefaaa2/terraform-guardrail/releases/latest/download/install.sh | bash
```
