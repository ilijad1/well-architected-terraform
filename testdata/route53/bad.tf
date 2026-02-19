resource "aws_route53_query_log" "bad" {
  zone_id = "Z789012"
}

resource "aws_route53_hosted_zone_dnssec" "bad" {
  hosted_zone_id = "Z789012"
  signing_status = "NOT_SIGNING"
}
