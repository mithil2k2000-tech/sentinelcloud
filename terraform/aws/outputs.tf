output "vpc_id" {
  value = module.network.vpc_id
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "customer_data_bucket" {
  value = module.storage.bucket_name
}

output "payment_service_role_arn" {
  value = module.iam.payment_service_role_arn
}

output "cloudtrail_arn" {
  value = module.logging.trail_arn
}
