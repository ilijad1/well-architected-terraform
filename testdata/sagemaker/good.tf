resource "aws_sagemaker_notebook_instance" "good" {
  name                    = "good-notebook"
  instance_type           = "ml.t2.medium"
  role_arn                = "arn:aws:iam::role/sagemaker"
  kms_key_id              = "arn:aws:kms:us-east-1:123:key/abc"
  direct_internet_access  = "Disabled"
  root_access             = "Disabled"
  subnet_id               = "subnet-1"
}

resource "aws_sagemaker_endpoint_configuration" "good" {
  name       = "good-endpoint"
  kms_key_id = "arn:aws:kms:us-east-1:123:key/abc"
}
