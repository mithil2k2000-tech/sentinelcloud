# Storage module — secure-by-default account for customer data.
#
# This is the module that would have caught "Storage bucket publicly
# accessible" in the IaC-scanning example from the roadmap: every knob
# below defaults closed, and the Azure Policy set in modules/policy
# additionally blocks any future drift toward public access.

resource "random_id" "suffix" {
  byte_length = 3
}

resource "azurerm_storage_account" "this" {
  name                = "st${var.project_name}${var.environment}${random_id.suffix.hex}"
  resource_group_name = var.resource_group_name
  location            = var.location

  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"

  # No public access, no shared-key auth (RBAC/Entra ID only), no public
  # blob containers by default.
  public_network_access_enabled   = false
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "customer_data" {
  name                  = "customer-data"
  storage_account_name  = azurerm_storage_account.this.name
  container_access_type = "private"
}

resource "azurerm_private_endpoint" "storage_blob" {
  name                = "pe-${var.project_name}-blob-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.data_subnet_id

  private_service_connection {
    name                           = "psc-blob"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  tags = var.tags
}
