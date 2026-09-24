output "kms_key_id" {
  value = google_kms_crypto_key.this.id
}

output "secret_id" {
  value = google_secret_manager_secret.app_secrets.secret_id
}
