output "resource_group_name" {
  value = module.network.resource_group_name
}

output "aks_cluster_id" {
  value = module.aks.cluster_id
}

output "key_vault_uri" {
  value = module.keyvault.key_vault_uri
}

output "storage_account_id" {
  value = module.storage.storage_account_id
}

output "log_analytics_workspace_id" {
  value = module.logging.workspace_id
}
