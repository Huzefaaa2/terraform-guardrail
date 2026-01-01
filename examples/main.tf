variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_db_instance" "primary" {
  allocated_storage = 10
  engine            = "postgres"
  password          = "super-secret"
}
