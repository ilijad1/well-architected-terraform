resource "aws_docdb_cluster" "good" {
  cluster_identifier              = "good-cluster"
  master_username                 = "admin"
  master_password                 = "password"
  storage_encrypted               = true
  deletion_protection             = true
  backup_retention_period         = 7
  enabled_cloudwatch_logs_exports = ["audit"]
}

resource "aws_docdb_cluster_parameter_group" "good" {
  family = "docdb5.0"
  name   = "good-params"

  parameter {
    name  = "tls"
    value = "enabled"
  }
}
