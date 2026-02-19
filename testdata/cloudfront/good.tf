resource "aws_cloudfront_distribution" "good" {
  enabled    = true
  web_acl_id = "arn:aws:wafv2:us-east-1:123:webacl"

  origin {
    domain_name = "example.com"
    origin_id   = "myOrigin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "myOrigin"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    minimum_protocol_version = "TLSv1.2_2021"
  }

  logging_config {
    bucket = "logs.s3.amazonaws.com"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}
