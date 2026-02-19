resource "aws_lambda_function" "bad" {
  function_name = "bad-func"
  runtime       = "python3.9"
  handler       = "main.handler"
  role          = "arn:aws:iam::role/lambda"
  filename      = "lambda.zip"

  environment {
    variables = { KEY = "value" }
  }
}

resource "aws_lambda_permission" "public" {
  statement_id  = "AllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "bad-func"
  principal     = "*"
}
