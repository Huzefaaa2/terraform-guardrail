# Compliance Rules

| Rule | Description | Severity |
| --- | --- | --- |
| TG001 | Sensitive variable missing `ephemeral = true` | Medium |
| TG002 | Hardcoded secret in config or tfvars | High |
| TG003 | Sensitive-looking value stored in state | High |
| TG004 | HCL parse error | Low |
| TG005 | Attribute not found in provider schema | Medium |

## Recommendations

- Use `ephemeral = true` for sensitive variables.
- Avoid hardcoding secrets in `.tf` or `.tfvars`.
- Keep secrets out of state using write-only or ephemeral values.
