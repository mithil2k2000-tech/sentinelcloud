output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "secret_arn" {
  value = aws_secretsmanager_secret.app_secrets.arn
}
