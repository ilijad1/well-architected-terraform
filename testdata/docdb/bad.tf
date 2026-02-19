resource "aws_docdb_cluster" "bad" {
  cluster_identifier  = "bad-cluster"
  master_username     = "admin"
  master_password     = "password"
  backup_retention_period = 1
}

resource "aws_docdb_cluster_parameter_group" "bad" {
  family = "docdb5.0"
  name   = "bad-params"
}
