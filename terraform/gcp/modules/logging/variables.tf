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

variable "log_retention_days" {
  description = "Lifecycle age (days) before exported audit logs are deleted from the log bucket."
  type        = number
  default     = 365
}

variable "labels" {
  type    = map(string)
  default = {}
}
