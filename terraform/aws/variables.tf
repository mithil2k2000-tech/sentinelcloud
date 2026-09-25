variable "project_name" {
  type    = string
  default = "csp"
}

variable "environment" {
  type    = string
  default = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  type    = string
  default = "eu-west-2" # London
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "allowed_admin_cidrs" {
  description = "CIDRs allowed to reach management-plane resources. Never default to 0.0.0.0/0."
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {
    project    = "cloud-security-platform"
    managed-by = "terraform"
  }
}
