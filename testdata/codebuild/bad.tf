resource "aws_codebuild_project" "bad" {
  name = "bad-project"

  artifacts {
    type                = "S3"
    encryption_disabled = true
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true

    environment_variable {
      name  = "DB_PASSWORD"
      value = "secret123"
    }
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/example/repo.git"
  }

  service_role = "arn:aws:iam::123:role/codebuild"
}
