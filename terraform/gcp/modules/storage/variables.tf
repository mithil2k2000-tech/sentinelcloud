variable "project_id" {
  type = string
}

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type = string
}

variable "kms_key_id" {
  description = "CMEK key from modules/secrets to encrypt this bucket with."
  type        = string
}

variable "payment_service_account_email" {
  type = string
}

variable "payment_data_access_role_id" {
  description = "Custom role ID from modules/iam (IAM-004) to bind at this bucket, instead of any built-in broad role."
  type        = string
}
