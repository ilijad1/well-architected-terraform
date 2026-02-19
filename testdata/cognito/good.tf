resource "aws_cognito_user_pool" "good" {
  name              = "good-pool"
  mfa_configuration = "ON"
  deletion_protection = "ACTIVE"

  password_policy {
    minimum_length    = 12
    require_uppercase = true
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}

resource "aws_cognito_identity_pool" "good" {
  identity_pool_name               = "good-pool"
  allow_unauthenticated_identities = false
}
