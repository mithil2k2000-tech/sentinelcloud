variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "aks_subnet_id" {
  type = string
}

variable "authorized_ip_ranges" {
  description = "CIDRs allowed to reach the AKS API server. Must not be empty in prod."
  type        = list(string)
  default     = []
}

variable "log_analytics_workspace_id" {
  description = "modules/logging's Log Analytics workspace ID (Phase 9) — wires Defender for Cloud's cluster-level findings into the same central workspace as everything else. Optional so the module still validates standalone."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
