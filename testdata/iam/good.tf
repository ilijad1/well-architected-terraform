data "aws_iam_policy_document" "specific" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  password_reuse_prevention    = 24
}

resource "aws_iam_role" "short_session" {
  name               = "short-session-role"
  assume_role_policy = "{}"
  max_session_duration = 3600
}

data "aws_iam_policy_document" "scoped_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
