variable "project_name" {
  description = "Short project name used as a naming prefix for all resources."
  type        = string
  default     = "csp" # cloud security platform
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod). Drives naming and policy strictness."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "uksouth"
}

variable "address_space" {
  description = "CIDR block for the VNet. Subnets are carved out of this."
  type        = string
  default     = "10.20.0.0/16"
}

variable "allowed_admin_cidrs" {
  description = <<-EOT
    CIDR ranges allowed to reach management-plane resources (bastion, AKS API
    server authorized ranges, etc). Never default this to 0.0.0.0/0 in a real
    deployment — set it explicitly per environment.
  EOT
  type    = list(string)
  default = []
}

variable "tags" {
  description = "Common tags applied to every resource for cost tracking and ownership."
  type        = map(string)
  default     = {
    project    = "cloud-security-platform"
    managed-by = "terraform"
  }
}
