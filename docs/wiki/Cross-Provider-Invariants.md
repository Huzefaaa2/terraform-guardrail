# Cross-Provider Invariants

Cross-provider invariants enforce the same platform intent across AWS, Azure, and GCP even when
each provider uses different resource names and attributes.

## Delivered in v3.0 Development

| Rule ID | Invariant | Providers | Purpose |
| --- | --- | --- | --- |
| `TG021` | Public exposure | AWS, Azure, GCP | Detect public storage, broad ingress, and public compute/database exposure |
| `TG022` | Storage encryption | AWS, Azure, GCP | Detect storage resources without provider-native encryption controls |
| `TG023` | Ownership metadata | AWS, Azure, GCP | Require consistent ownership/environment metadata through tags or labels |

These rules complement the original provider-specific rules. For example, an AWS S3 bucket without
default encryption can produce both:

- `TG011` for the AWS-specific S3 encryption rule.
- `TG022` for the cross-provider storage encryption invariant.

The provider-specific finding remains first for backward compatibility. The invariant finding adds
common metadata:

```json
{
  "rule_id": "TG022",
  "detail": {
    "invariant": "storage_encryption",
    "provider": "aws",
    "resource": "aws_s3_bucket.logs"
  }
}
```

## Covered Patterns

Public exposure:

- AWS S3 public ACLs, public access block disabled, world-open security groups, public compute,
  public RDS.
- Azure storage public network access and world-open network security rules.
- GCP storage public ACLs and world-open firewall rules.

Storage encryption:

- AWS S3, RDS, and EBS encryption controls.
- Azure storage account infrastructure encryption and managed disk encryption sets.
- GCP storage bucket encryption and compute disk encryption keys.

Ownership metadata:

- AWS/Azure `tags` or `tags_all`.
- GCP `labels`.

## Example

```hcl
resource "google_storage_bucket" "logs" {
  name           = "logs"
  location       = "US"
  predefined_acl = "publicRead"
}
```

The scan emits `TG021` with `provider=gcp` and `invariant=public_exposure`.

## Status

Delivered as the third v3.0 Ecosystem capability.
