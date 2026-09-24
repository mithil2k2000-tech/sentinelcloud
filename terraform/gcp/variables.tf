variable "project_id" {
  description = "GCP project ID to deploy into."
  type        = string
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
  default = "europe-west2" # London
}

variable "project_name" {
  type    = string
  default = "csp"
}

variable "allowed_admin_cidrs" {
  description = "CIDRs allowed to reach management-plane resources. Never default to 0.0.0.0/0."
  type        = list(string)
  default     = []
}

variable "labels" {
  type = map(string)
  default = {
    project    = "cloud-security-platform"
    managed-by = "terraform"
  }
}
