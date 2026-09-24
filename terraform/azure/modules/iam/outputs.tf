output "payment_service_principal_id" {
  value = azuread_service_principal.payment_service.object_id
}

output "account_service_principal_id" {
  value = azuread_service_principal.account_service.object_id
}

output "security_auditor_role_id" {
  value = azurerm_role_definition.security_auditor.role_definition_resource_id
}
