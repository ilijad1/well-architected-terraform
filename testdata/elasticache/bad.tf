resource "aws_elasticache_replication_group" "bad" {
  replication_group_id = "bad-rg"
  description          = "Bad replication group"
  num_cache_clusters   = 1
}

resource "aws_elasticache_cluster" "single_az" {
  cluster_id      = "single-az-cluster"
  engine          = "memcached"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
  az_mode         = "single-az"
}
