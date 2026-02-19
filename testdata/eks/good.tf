resource "aws_eks_cluster" "good" {
  name     = "good-cluster"
  role_arn = "arn:aws:iam::role/eks"
  enabled_cluster_log_types = ["api", "audit"]

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = "arn:aws:kms:us-east-1:123:key/abc"
    }
  }

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids              = ["subnet-1"]
  }
}

resource "aws_eks_node_group" "good" {
  cluster_name    = "good-cluster"
  node_group_name = "workers"
  node_role_arn   = "arn:aws:iam::role/node"
  subnet_ids      = ["subnet-1"]
  tags = { Environment = "prod" }
}
