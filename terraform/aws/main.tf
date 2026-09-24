# Root module — AWS equivalent of terraform/azure/main.tf and
# terraform/gcp/main.tf. Note the dependency order: eks must exist before
# iam (IRSA needs the cluster's OIDC provider), and secrets/storage before
# iam (the policy needs the bucket ARN to scope to).

module "network" {
  source = "./modules/network"

  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  allowed_admin_cidrs = var.allowed_admin_cidrs
  tags                = var.tags
}

module "secrets" {
  source = "./modules/secrets"

  project_name = var.project_name
  environment  = var.environment
}

module "storage" {
  source = "./modules/storage"

  project_name = var.project_name
  environment  = var.environment
  kms_key_arn  = module.secrets.kms_key_arn
}

module "policy" {
  source = "./modules/policy"

  project_name = var.project_name
  environment  = var.environment
}

module "eks" {
  source = "./modules/eks"

  project_name           = var.project_name
  environment            = var.environment
  vpc_id                 = module.network.vpc_id
  eks_subnet_ids         = [module.network.subnet_ids["eks"]]
  eks_security_group_id  = module.network.security_group_ids["eks"]
  authorized_cidrs       = var.allowed_admin_cidrs
}

module "iam" {
  source = "./modules/iam"

  project_name         = var.project_name
  environment          = var.environment
  oidc_provider_arn    = module.eks.oidc_provider_arn
  oidc_provider_url    = module.eks.oidc_provider_url
  payments_bucket_arn  = module.storage.bucket_arn
  app_secrets_arn      = module.secrets.secret_arn
}

module "mesh" {
  source = "./modules/mesh"

  # Phase 4 (Zero Trust): closes RR-03/RR-04 — see modules/mesh's own
  # header comment for what this installs.
}

module "logging" {
  source = "./modules/logging"

  # Phase 9: closes RR-01 (no centralized audit logging) — see
  # modules/logging's own header comment for what this wires up.
  project_name         = var.project_name
  environment          = var.environment
  kms_key_arn          = module.secrets.kms_key_arn
  payments_bucket_arn  = module.storage.bucket_arn
  tags                 = var.tags
}
