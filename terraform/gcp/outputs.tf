output "network_name" {
  value = module.network.network_name
}

output "gke_cluster_name" {
  value = module.gke.cluster_name
}

output "customer_data_bucket" {
  value = module.storage.bucket_name
}

output "kms_key_id" {
  value = module.secrets.kms_key_id
}

output "audit_log_bucket" {
  value = module.logging.log_bucket_name
}
