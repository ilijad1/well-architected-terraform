resource "aws_ecr_repository" "bad" {
  name = "bad-repo"
}

resource "aws_ecr_lifecycle_policy" "bad" {
  repository = aws_ecr_repository.bad.name
}
