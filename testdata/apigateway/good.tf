resource "aws_api_gateway_stage" "good" {
  deployment_id        = "abc123"
  rest_api_id          = "api123"
  stage_name           = "prod"
  xray_tracing_enabled = true
  web_acl_arn          = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc123"

  access_log_settings {
    destination_arn = "arn:aws:logs:us-east-1:123:log-group:api"
  }
}

resource "aws_apigatewayv2_stage" "good" {
  api_id = "api123"
  name   = "prod"

  access_log_settings {
    destination_arn = "arn:aws:logs:us-east-1:123:log-group:api"
  }
}

resource "aws_api_gateway_method_settings" "good" {
  rest_api_id = "api123"
  stage_name  = "prod"
  method_path = "*/*"

  settings {
    cache_data_encrypted = true
  }
}
