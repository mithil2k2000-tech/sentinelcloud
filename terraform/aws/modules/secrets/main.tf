# Secrets module — customer-managed KMS key + Secrets Manager secret. The
# AWS equivalent of Azure Key Vault / GCP Secret Manager+KMS.

resource "aws_kms_key" "this" {
  description             = "CMK for ${var.project_name}-${var.environment} secrets and data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.this.key_id
}

resource "aws_secretsmanager_secret" "app_secrets" {
  name       = "${var.project_name}-app-secrets-${var.environment}"
  kms_key_id = aws_kms_key.this.arn

  recovery_window_in_days = 30 # blocks instant/accidental permanent deletion
}
