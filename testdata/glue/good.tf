resource "aws_glue_security_configuration" "good" {
  name = "good-security-config"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "SSE-KMS"
      kms_key_arn                = "arn:aws:kms:us-east-1:123456789012:key/example"
    }

    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "CSE-KMS"
      kms_key_arn                   = "arn:aws:kms:us-east-1:123456789012:key/example"
    }

    s3_encryption {
      s3_encryption_mode = "SSE-KMS"
      kms_key_arn        = "arn:aws:kms:us-east-1:123456789012:key/example"
    }
  }
}

resource "aws_glue_data_catalog_encryption_settings" "good" {
  data_catalog_encryption_settings {
    connection_password_encryption {
      return_connection_password_encrypted = true
      aws_kms_key_id                       = "arn:aws:kms:us-east-1:123456789012:key/example"
    }

    encryption_at_rest {
      catalog_encryption_mode = "SSE-KMS"
      sse_aws_kms_key_id      = "arn:aws:kms:us-east-1:123456789012:key/example"
    }
  }
}
