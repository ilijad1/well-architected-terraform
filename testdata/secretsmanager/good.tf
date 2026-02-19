resource "aws_secretsmanager_secret" "good" {
  name       = "good-secret"
  kms_key_id = "arn:aws:kms:us-east-1:123:key/abc"
  tags       = { Environment = "prod" }
}

resource "aws_secretsmanager_secret_rotation" "good" {
  secret_id           = "arn:aws:secretsmanager:us-east-1:123:secret:good"
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123:function:rotate"

  rotation_rules {
    automatically_after_days = 30
  }
}
