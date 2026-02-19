resource "aws_ecr_repository" "good" {
  name                 = "good-repo"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = "arn:aws:kms:us-east-1:123:key/abc"
  }

  tags = {
    Environment = "prod"
  }
}

resource "aws_ecr_lifecycle_policy" "good" {
  repository = aws_ecr_repository.good.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 30 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 30
      }
      action = {
        type = "expire"
      }
    }]
  })
}
