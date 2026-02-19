resource "aws_opensearch_domain" "bad" {
  domain_name    = "bad-domain"
  engine_version = "OpenSearch_2.5"
}
