resource "aws_codebuild_project" "good" {
  name = "good-project"

  artifacts {
    type = "S3"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:5.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/example/repo.git"
  }

  service_role = "arn:aws:iam::123:role/codebuild"

  logs_config {
    cloudwatch_logs {
      group_name = "codebuild-logs"
    }
  }

  vpc_config {
    vpc_id             = "vpc-123"
    subnets            = ["subnet-123"]
    security_group_ids = ["sg-123"]
  }
}
