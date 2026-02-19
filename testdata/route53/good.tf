resource "aws_route53_query_log" "good" {
  zone_id                  = "Z123456"
  cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/example"
}

resource "aws_route53_hosted_zone_dnssec" "good" {
  hosted_zone_id = "Z123456"
  signing_status = "SIGNING"
}
