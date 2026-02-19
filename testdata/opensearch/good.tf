resource "aws_opensearch_domain" "good" {
  domain_name    = "good-domain"
  engine_version = "OpenSearch_2.5"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  vpc_options {
    subnet_ids = ["subnet-123"]
  }

  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123:log-group:audit"
  }

  advanced_security_options {
    enabled = true
  }

  tags = {
    Environment = "prod"
  }
}
