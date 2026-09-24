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

variable "aks_cluster_id" {
  description = "modules/aks's cluster_id — diagnostic settings are wired to this."
  type        = string
}

variable "key_vault_id" {
  description = "modules/keyvault's key_vault_id — diagnostic settings are wired to this."
  type        = string
}

variable "storage_account_id" {
  description = "modules/storage's storage_account_id — diagnostic settings are wired to this."
  type        = string
}

variable "log_retention_days" {
  description = "Log Analytics workspace retention. 90 days is the Azure default tier before extra cost kicks in."
  type        = number
  default     = 90
}

variable "tags" {
  type    = map(string)
  default = {}
}
