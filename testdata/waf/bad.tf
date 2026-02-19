resource "aws_wafv2_web_acl" "bad" {
  name  = "bad-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "bad-acl"
  }
}
