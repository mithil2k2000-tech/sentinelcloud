variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "eks_subnet_ids" {
  type = list(string)
}

variable "eks_security_group_id" {
  type = string
}

variable "authorized_cidrs" {
  description = "CIDRs allowed to reach the EKS public API endpoint. Empty disables public access entirely."
  type        = list(string)
  default     = []
}
