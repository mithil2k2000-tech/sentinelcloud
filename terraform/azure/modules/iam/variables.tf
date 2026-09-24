variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "subscription_scope" {
  description = "Scope (e.g. subscription or resource group ID) that custom role definitions are assignable against."
  type        = string
}

variable "payments_db_scope" {
  description = "Resource ID (or narrower, e.g. a specific container/table) that the payment-service workload identity may access. Deliberately narrow — this is the control for the 'payment service has excessive access to customer data' finding."
  type        = string
}

variable "account_service_secrets_scope" {
  description = "Resource ID (the Key Vault itself) that the account-service workload identity may access (RR-02)."
  type        = string
}
