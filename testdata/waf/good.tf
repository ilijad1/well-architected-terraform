resource "aws_wafv2_web_acl" "good" {
  name  = "good-acl"
  scope = "REGIONAL"

  default_action {
    block {}
  }

  rule {
    name     = "rate-limit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "good-acl"
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "good" {
  resource_arn            = "arn:aws:wafv2:us-east-1:123:regional/webacl/good/abc"
  log_destination_configs = ["arn:aws:firehose:us-east-1:123:deliverystream/waf"]
}
