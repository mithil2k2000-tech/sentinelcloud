output "storage_account_id" {
  value = azurerm_storage_account.this.id
}

output "customer_data_container_name" {
  value = azurerm_storage_container.customer_data.name
}
