resource "aws_emr_cluster" "bad" {
  name          = "bad-emr"
  release_label = "emr-6.0.0"
  service_role  = "arn:aws:iam::123456789012:role/emr"
}
