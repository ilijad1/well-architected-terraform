resource "aws_ecs_cluster" "bad" {
  name = "bad-cluster"
}

resource "aws_ecs_task_definition" "bad" {
  family = "bad-task"

  container_definitions = "[{\"name\":\"app\",\"image\":\"nginx:latest\",\"essential\":true,\"privileged\":true,\"environment\":[{\"name\":\"DB_PASSWORD\",\"value\":\"secret123\"}]}]"
}
