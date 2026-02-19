resource "aws_kinesis_stream" "bad" {
  name        = "bad-stream"
  shard_count = 1
}
