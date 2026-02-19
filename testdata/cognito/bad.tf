resource "aws_cognito_user_pool" "bad" {
  name              = "bad-pool"
  mfa_configuration = "OFF"
}

resource "aws_cognito_identity_pool" "bad" {
  identity_pool_name               = "bad-pool"
  allow_unauthenticated_identities = true
}
