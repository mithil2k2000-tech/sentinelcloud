variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  description = "modules/secrets's KMS key — encrypts the trail's S3 objects and CloudWatch Logs."
  type        = string
}

variable "payments_bucket_arn" {
  description = "modules/storage's customer-data bucket ARN — CloudTrail logs object-level (data) events for it, not just management events."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}
