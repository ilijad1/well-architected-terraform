resource "aws_inspector2_enabler" "main" {
  account_ids    = ["123456789012"]
  resource_types = ["ECR", "EC2", "LAMBDA"]
}
