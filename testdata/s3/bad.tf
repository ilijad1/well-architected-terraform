resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"
}

resource "aws_s3_bucket_public_access_block" "partial_block" {
  bucket = "my-unencrypted-bucket"

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_account_public_access_block" "partial" {
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "no_enforced" {
  bucket = "my-unencrypted-bucket"

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
