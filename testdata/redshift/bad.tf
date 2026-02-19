resource "aws_redshift_cluster" "bad" {
  cluster_identifier  = "bad-cluster"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = "Password1"
  publicly_accessible = true
}

resource "aws_redshift_parameter_group" "bad" {
  name   = "bad-params"
  family = "redshift-1.0"
}
