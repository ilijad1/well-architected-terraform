resource "aws_msk_cluster" "good" {
  cluster_name           = "good-cluster"
  kafka_version          = "3.4.0"
  number_of_broker_nodes = 3
  enhanced_monitoring    = "PER_BROKER"

  broker_node_group_info {
    instance_type  = "kafka.m5.large"
    client_subnets = ["subnet-1", "subnet-2", "subnet-3"]
    security_groups = ["sg-1"]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = "/aws/msk/good"
      }
    }
  }
}
