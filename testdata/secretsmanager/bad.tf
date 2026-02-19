resource "aws_secretsmanager_secret" "bad" {
  name = "bad-secret"
}

resource "aws_secretsmanager_secret_rotation" "bad" {
  secret_id = "arn:aws:secretsmanager:us-east-1:123:secret:bad"
}
