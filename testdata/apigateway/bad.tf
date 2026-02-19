resource "aws_api_gateway_stage" "bad" {
  deployment_id = "abc123"
  rest_api_id   = "api123"
  stage_name    = "prod"
}

resource "aws_apigatewayv2_stage" "bad" {
  api_id = "api123"
  name   = "prod"
}

resource "aws_api_gateway_method_settings" "bad" {
  rest_api_id = "api123"
  stage_name  = "prod"
  method_path = "*/*"

  settings {
    cache_data_encrypted = false
  }
}
