resource "aws_glue_security_configuration" "bad" {
  name = "bad-security-config"
}

resource "aws_glue_data_catalog_encryption_settings" "bad" {
  data_catalog_encryption_settings {
    connection_password_encryption {
      return_connection_password_encrypted = false
    }

    encryption_at_rest {
      catalog_encryption_mode = "DISABLED"
    }
  }
}
