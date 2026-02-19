resource "aws_ecs_cluster" "good" {
  name = "good-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
    }
  }

  tags = {
    Environment = "prod"
  }
}

resource "aws_ecs_task_definition" "good" {
  family       = "good-task"
  network_mode = "awsvpc"
  cpu          = "256"
  memory       = "512"

  container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"essential\":true,\"privileged\":false,\"readonlyRootFilesystem\":true,\"environment\":[{\"name\":\"APP_ENV\",\"value\":\"production\"}],\"logConfiguration\":{\"logDriver\":\"awslogs\"}}]"
}
