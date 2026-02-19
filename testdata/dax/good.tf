resource "aws_dax_cluster" "good" {
  cluster_name       = "good-dax"
  iam_role_arn       = "arn:aws:iam::123456789012:role/dax"
  node_type          = "dax.r4.large"
  replication_factor = 1
  cluster_endpoint_encryption_type = "TLS"

  server_side_encryption {
    enabled = true
  }
}
