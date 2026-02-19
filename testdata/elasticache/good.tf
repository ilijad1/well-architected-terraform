resource "aws_elasticache_replication_group" "good" {
  replication_group_id = "good-rg"
  description          = "Good replication group"
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  automatic_failover_enabled  = true
  num_cache_clusters          = 3
}

resource "aws_elasticache_cluster" "multi_az" {
  cluster_id      = "multi-az-cluster"
  engine          = "memcached"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 3
  az_mode         = "cross-az"
}
