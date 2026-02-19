resource "aws_msk_cluster" "bad" {
  cluster_name           = "bad-cluster"
  kafka_version          = "3.4.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type  = "kafka.m5.large"
    client_subnets = ["subnet-1", "subnet-2", "subnet-3"]
    security_groups = ["sg-1"]
  }
}
