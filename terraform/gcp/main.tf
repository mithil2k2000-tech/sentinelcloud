# Root module — GCP equivalent of terraform/azure/main.tf.

module "network" {
  source = "./modules/network"

  project_id          = var.project_id
  project_name        = var.project_name
  environment         = var.environment
  region              = var.region
  allowed_admin_cidrs = var.allowed_admin_cidrs
}

module "iam" {
  source = "./modules/iam"

  project_id   = var.project_id
  project_name = var.project_name
  environment  = var.environment
}

module "secrets" {
  source = "./modules/secrets"

  project_id   = var.project_id
  project_name = var.project_name
  environment  = var.environment
  region       = var.region

  # Phase 4 (Zero Trust, RR-02).
  account_service_account_email          = module.iam.account_service_account_email
  account_service_secrets_access_role_id = module.iam.account_service_secrets_access_role_id
}

module "storage" {
  source = "./modules/storage"

  project_id                    = var.project_id
  project_name                  = var.project_name
  environment                   = var.environment
  region                        = var.region
  kms_key_id                    = module.secrets.kms_key_id
  payment_service_account_email = module.iam.payment_service_account_email
  payment_data_access_role_id   = module.iam.payment_data_access_role_id
}

module "policy" {
  source = "./modules/policy"

  project_id = var.project_id
}

module "logging" {
  source = "./modules/logging"

  # Phase 9: closes RR-01 (no centralized audit logging) — see
  # modules/logging's own header comment for what this wires up.
  project_id   = var.project_id
  project_name = var.project_name
  environment  = var.environment
  region       = var.region
}

module "gke" {
  source = "./modules/gke"

  project_id           = var.project_id
  project_name         = var.project_name
  environment          = var.environment
  region               = var.region
  network_name         = module.network.network_name
  gke_subnet_self_link = module.network.subnet_self_links["gke"]
  authorized_cidrs     = var.allowed_admin_cidrs
}

module "mesh" {
  source = "./modules/mesh"

  # Phase 4 (Zero Trust): closes RR-03/RR-04 — see modules/mesh's own
  # header comment for what this installs.
}
