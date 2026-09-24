output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "log_bucket_name" {
  value = aws_s3_bucket.trail.id
}

output "cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.trail.name
}
