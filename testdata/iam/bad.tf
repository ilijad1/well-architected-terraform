data "aws_iam_policy_document" "wildcard_actions" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "wildcard_s3" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length      = 8
  password_reuse_prevention    = 3
}

resource "aws_iam_user_policy" "inline" {
  name   = "inline-policy"
  user   = "my-user"
  policy = "{}"
}

resource "aws_iam_role" "long_session" {
  name               = "long-session-role"
  assume_role_policy = "{}"
  max_session_duration = 43200
}

data "aws_iam_policy_document" "full_admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_user" "standalone" {
  name = "standalone-user"
}
