# Root module — wires the network, IAM, Key Vault, Storage, Policy and AKS
# modules together for one environment. Run per-environment via a tfvars
# file (dev/staging/prod) or a workspace.

data "azurerm_client_config" "current" {}

module "network" {
  source = "./modules/network"

  project_name        = var.project_name
  environment         = var.environment
  location            = var.location
  address_space       = var.address_space
  allowed_admin_cidrs = var.allowed_admin_cidrs
  tags                = var.tags
}

module "iam" {
  source = "./modules/iam"

  project_name       = var.project_name
  environment        = var.environment
  subscription_scope = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  # In a real deployment this narrows to the specific Cosmos/SQL container
  # resource ID, not the whole resource group.
  payments_db_scope = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${module.network.resource_group_name}"
  # Phase 4 (Zero Trust, RR-02): account-service's role IS scoped to a
  # specific resource — the Key Vault itself already exists, unlike
  # payment-service's still-pending database resource above.
  account_service_secrets_scope = module.keyvault.key_vault_id
}

module "keyvault" {
  source = "./modules/keyvault"

  project_name        = var.project_name
  environment         = var.environment
  location            = var.location
  resource_group_name = module.network.resource_group_name
  data_subnet_id      = module.network.subnet_ids["data"]
  tenant_id           = data.azurerm_client_config.current.tenant_id
  tags                = var.tags
}

module "storage" {
  source = "./modules/storage"

  project_name        = var.project_name
  environment         = var.environment
  location            = var.location
  resource_group_name = module.network.resource_group_name
  data_subnet_id      = module.network.subnet_ids["data"]
  tags                = var.tags
}

module "policy" {
  source = "./modules/policy"

  management_group_or_subscription_id = data.azurerm_client_config.current.subscription_id
}

module "aks" {
  source = "./modules/aks"

  project_name               = var.project_name
  environment                = var.environment
  location                   = var.location
  resource_group_name        = module.network.resource_group_name
  aks_subnet_id              = module.network.subnet_ids["aks"]
  authorized_ip_ranges       = var.allowed_admin_cidrs
  log_analytics_workspace_id = module.logging.workspace_id
  tags                       = var.tags
}

module "logging" {
  source = "./modules/logging"

  # Lives in the mgmt trust boundary — see modules/network's subnet layout.
  # This is the Phase 9 piece: closes RR-01 (no centralized audit logging).
  project_name        = var.project_name
  environment         = var.environment
  location            = var.location
  resource_group_name = module.network.resource_group_name
  aks_cluster_id      = module.aks.cluster_id
  key_vault_id        = module.keyvault.key_vault_id
  storage_account_id  = module.storage.storage_account_id
  tags                = var.tags
}

module "mesh" {
  source = "./modules/mesh"

  # Phase 4 (Zero Trust): closes RR-03/RR-04 — see modules/mesh's own
  # header comment for what this installs.
}
