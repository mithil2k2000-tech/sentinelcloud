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

variable "account_service_account_email" {
  description = "modules/iam's account-service workload identity — bound to the secret below, scoped to nothing else (RR-02)."
  type        = string
}

variable "account_service_secrets_access_role_id" {
  description = "modules/iam's account_service_secrets_access custom role id."
  type        = string
}
