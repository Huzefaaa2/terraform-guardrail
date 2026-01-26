variable "db_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "aws_s3_bucket" "good" {
  bucket = "guardrail-good-example"
}
