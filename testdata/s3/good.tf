resource "aws_s3_bucket" "encrypted_bucket" {
  bucket = "my-encrypted-bucket"

  tags = {
    Environment = "production"
    Project     = "example"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted_bucket" {
  bucket = "my-encrypted-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123:key/abc"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "encrypted_bucket" {
  bucket = "my-encrypted-bucket"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "encrypted_bucket" {
  bucket = "my-encrypted-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "encrypted_bucket" {
  bucket        = "my-encrypted-bucket"
  target_bucket = "my-log-bucket"
  target_prefix = "log/"
}

resource "aws_s3_account_public_access_block" "all_blocked" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "enforced" {
  bucket = "my-encrypted-bucket"

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
