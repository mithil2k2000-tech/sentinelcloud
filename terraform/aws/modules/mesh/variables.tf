variable "istio_version" {
  description = "Istio Helm chart version. Pinned rather than 'latest' so a mesh upgrade is a deliberate, reviewed change."
  type        = string
  default     = "1.23.2"
}

variable "app_namespace" {
  description = "Namespace payment-service/account-service/notification-service/api-gateway run in — gets sidecar injection enabled."
  type        = string
  default     = "app"
}
