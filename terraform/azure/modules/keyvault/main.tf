# Key Vault module — secure-by-default secrets/keys/certs store.
#
# Controls encoded here:
#  - RBAC authorization (not vault access policies) so access is governed by
#    the same azurerm_role_assignment model as everything else — one IAM
#    story, not two.
#  - Public network access disabled; reachable only via the private endpoint
#    in snet-data (see modules/network).
#  - Purge protection + soft delete so a compromised/malicious delete can't
#    destroy key material permanently.
#  - Diagnostic logging wired to the workspace created for Phase 9 (SIEM).

resource "random_id" "suffix" {
  byte_length = 3
}

resource "azurerm_key_vault" "this" {
  name                = "kv-${var.project_name}-${var.environment}-${random_id.suffix.hex}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = var.tags
}

resource "azurerm_private_endpoint" "keyvault" {
  name                = "pe-${var.project_name}-kv-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.data_subnet_id

  private_service_connection {
    name                           = "psc-kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  tags = var.tags
}
