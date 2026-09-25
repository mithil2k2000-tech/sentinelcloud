# AKS module — hardened baseline for the "deliberately vulnerable
# environment" in Phase 5 to be measured against.
#
# Hardening applied here (the things Phase 5's scanner should find MISSING
# if someone reverts them):
#   - private_cluster_enabled: API server has no public endpoint
#   - RBAC enabled, local accounts disabled (Entra ID-only auth)
#   - Azure Policy add-on enabled -> enforces the guardrail-baseline initiative
#     inside the cluster (blocks privileged containers, host namespace use)
#   - Azure CNI + network policy (Calico/Azure) for pod-to-pod segmentation
#   - Workload Identity + OIDC issuer enabled instead of pod-level secrets
#   - No default node pool running as cluster-admin; system/user pool split

resource "azurerm_kubernetes_cluster" "this" {
  name                = "aks-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = "${var.project_name}-${var.environment}"

  private_cluster_enabled = true
  local_account_disabled  = true

  api_server_access_profile {
    authorized_ip_ranges = var.authorized_ip_ranges
  }

  default_node_pool {
    name                         = "system"
    vm_size                      = "Standard_D2s_v5"
    node_count                   = 2
    vnet_subnet_id               = var.aks_subnet_id
    only_critical_addons_enabled = true # system pool runs no app workloads
  }

  identity {
    type = "SystemAssigned"
  }

  azure_active_directory_role_based_access_control {
    managed            = true # AKS-managed Entra ID integration, not the legacy client/server-app-id flow
    azure_rbac_enabled = true
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }

  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  azure_policy_enabled = true

  microsoft_defender {
    log_analytics_workspace_id = var.log_analytics_workspace_id # wired from modules/logging, Phase 9
  }

  tags = var.tags
}

resource "azurerm_kubernetes_cluster_node_pool" "user" {
  name                  = "user"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size               = "Standard_D4s_v5"
  node_count            = 2
  vnet_subnet_id        = var.aks_subnet_id
  mode                  = "User"
}
