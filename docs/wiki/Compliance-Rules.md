# Compliance Rules

| Rule | Description | Severity |
| --- | --- | --- |
| TG001 | Sensitive variable missing `ephemeral = true` | Medium |
| TG002 | Hardcoded secret in config or tfvars | High |
| TG003 | Sensitive-looking value stored in state | High |
| TG004 | HCL parse error | Low |
| TG005 | Attribute not found in provider schema | Medium |
| TG006 | Public S3 bucket ACL detected | High |
| TG007 | Public S3 access block disabled | High |
| TG008 | Security group ingress open to the world | High |
| TG009 | IAM policy wildcard permissions | High |
| TG010 | Public IP association enabled on compute | Medium |
| TG011 | S3 bucket missing default encryption | Medium |
| TG012 | RDS storage not encrypted | Medium |
| TG013 | Load balancer listener uses HTTP | Medium |
| TG014 | Instance missing subnet/VPC boundary | Low |
| TG015 | RDS instance publicly accessible | High |
| TG016 | Missing mandatory resource tags | Low |
| TG017 | Resource region/location not in allowed list | Medium |
| TG018 | Instance type or SKU not in allowed list | Medium |
| TG019 | Azure storage account public network access enabled | Medium |
| TG020 | EBS volume not encrypted | Medium |

## Recommendations

- Use `ephemeral = true` for sensitive variables.
- Avoid hardcoding secrets in `.tf` or `.tfvars`.
- Keep secrets out of state using write-only or ephemeral values.

## Supported providers

- AWS
- Azure
- GCP
- Kubernetes
- Helm
- OCI
- Vault
- Alicloud
- vSphere
