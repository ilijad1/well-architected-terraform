resource "aws_athena_workgroup" "good" {
  name = "good-workgroup"

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = "arn:aws:kms:us-east-1:123456789012:key/example"
      }
    }
  }
}
