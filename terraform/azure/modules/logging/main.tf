# Logging module — Phase 9 (SIEM + Detection), v1 spec §16.
#
# A single Log Analytics workspace as the "mgmt" trust boundary's one real
# resident, with diagnostic settings wired from AKS, Key Vault and Storage
# into it. This is the concrete infrastructure behind flipping
# architecture-hardened.json's "logging.enabled" from false to true, and
# it's what closes RR-01 in threat-model/residual-risk-register.md.
#
# What this does NOT yet do (documented, not hidden — see
# docs/phase9-siem-detection.md): wire an actual alert/notification action
# group, or add blob-service-level diagnostic settings for
# StorageRead/Write/Delete logs (those need a separate diagnostic setting
# scoped to `${storage_account_id}/blobServices/default`, not the account
# itself) — left as a follow-up, tracked there rather than silently
# skipped.

resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${var.project_name}-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "diag-aks-${var.environment}"
  target_resource_id         = var.aks_cluster_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "allLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-keyvault-${var.environment}"
  target_resource_id         = var.key_vault_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "audit"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage_account" {
  name                       = "diag-storage-${var.environment}"
  target_resource_id         = var.storage_account_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  metric {
    category = "Transaction"
    enabled  = true
  }
}
