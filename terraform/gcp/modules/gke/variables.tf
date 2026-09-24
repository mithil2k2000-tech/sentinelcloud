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

variable "network_name" {
  type = string
}

variable "gke_subnet_self_link" {
  type = string
}

variable "authorized_cidrs" {
  description = "CIDRs allowed to reach the GKE control plane. Must not be empty in prod."
  type        = list(string)
  default     = []
}
