variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "oidc_provider_arn" {
  description = "EKS cluster's OIDC provider ARN, for IRSA trust policies. Passed in from modules/eks."
  type        = string
}

variable "oidc_provider_url" {
  description = "EKS cluster's OIDC issuer URL (without https://), for the trust policy condition."
  type        = string
}

variable "payments_bucket_arn" {
  description = "ARN of the specific S3 bucket payment-service may access. Deliberately narrow."
  type        = string
}

variable "app_secrets_arn" {
  description = "ARN of the specific Secrets Manager secret account-service may access (RR-02). Deliberately narrow."
  type        = string
}
