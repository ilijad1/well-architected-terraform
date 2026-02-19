resource "aws_eks_cluster" "bad" {
  name     = "bad-cluster"
  role_arn = "arn:aws:iam::role/eks"

  vpc_config {
    subnet_ids = ["subnet-1"]
  }
}

resource "aws_eks_node_group" "bad" {
  cluster_name    = "bad-cluster"
  node_group_name = "workers"
  node_role_arn   = "arn:aws:iam::role/node"
  subnet_ids      = ["subnet-1"]
}
