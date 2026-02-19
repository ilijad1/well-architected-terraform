resource "aws_lambda_function" "good" {
  function_name = "good-func"
  runtime       = "python3.9"
  handler       = "main.handler"
  role          = "arn:aws:iam::role/lambda"
  filename      = "lambda.zip"
  kms_key_arn   = "arn:aws:kms:us-east-1:123:key/abc"
  tags          = { Environment = "prod" }
  reserved_concurrent_executions = 100

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123:dlq"
  }

  environment {
    variables = { KEY = "value" }
  }

  vpc_config {
    subnet_ids         = ["subnet-123"]
    security_group_ids = ["sg-123"]
  }
}

resource "aws_lambda_permission" "specific_principal" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "good-func"
  principal     = "apigateway.amazonaws.com"
}
