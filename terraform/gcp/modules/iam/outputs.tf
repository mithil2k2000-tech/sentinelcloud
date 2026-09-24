output "payment_service_account_email" {
  value = google_service_account.payment_service.email
}

output "account_service_account_email" {
  value = google_service_account.account_service.email
}

output "payment_data_access_role_id" {
  value = google_project_iam_custom_role.payment_data_access.id
}

output "account_service_secrets_access_role_id" {
  value = google_project_iam_custom_role.account_service_secrets_access.id
}
