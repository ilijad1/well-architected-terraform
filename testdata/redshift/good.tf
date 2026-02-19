resource "aws_redshift_cluster" "good" {
  cluster_identifier  = "good-cluster"
  node_type           = "dc2.large"
  master_username     = "admin"
  master_password     = "Password1"
  encrypted           = true
  publicly_accessible = false
  enhanced_vpc_routing = true
  cluster_type        = "multi-node"
  number_of_nodes     = 2

  automated_snapshot_retention_period = 7

  logging {
    enable = true
  }

  tags = {
    Environment = "prod"
  }
}

resource "aws_redshift_parameter_group" "good" {
  name   = "good-params"
  family = "redshift-1.0"

  parameter {
    name  = "require_ssl"
    value = "true"
  }
}
