resource "aws_neptune_cluster" "bad" {
  cluster_identifier      = "bad-cluster"
  engine                  = "neptune"
  backup_retention_period = 1
}
