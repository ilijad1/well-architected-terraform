resource "aws_sagemaker_notebook_instance" "bad" {
  name          = "bad-notebook"
  instance_type = "ml.t2.medium"
  role_arn      = "arn:aws:iam::role/sagemaker"
}

resource "aws_sagemaker_endpoint_configuration" "bad" {
  name = "bad-endpoint"
}
