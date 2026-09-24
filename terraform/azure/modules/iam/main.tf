# IAM module — Entra ID workload identities + least-privilege custom roles.
#
# Principle: no service ever gets a built-in "Contributor"/"Owner" role.
# Every workload gets a purpose-built custom role scoped to exactly the
# resource(s) it needs, nothing more. This directly encodes the
# threat-model → control → policy chain from the roadmap:
#
#   Finding:  Payment service → unrestricted database access
#   Control:  IAM-004 — least-privilege IAM + segmentation
#   Policy:   Payment service may access only payments_db.transactions

# --- Workload identities (one per microservice, no shared credentials) ---

resource "azuread_application" "payment_service" {
  display_name = "${var.project_name}-payment-service-${var.environment}"
}

resource "azuread_service_principal" "payment_service" {
  client_id = azuread_application.payment_service.client_id
}

resource "azuread_application" "account_service" {
  display_name = "${var.project_name}-account-service-${var.environment}"
}

resource "azuread_service_principal" "account_service" {
  client_id = azuread_application.account_service.client_id
}

# --- Custom roles: named after the control they satisfy ------------------

resource "azurerm_role_definition" "payment_data_access" {
  name        = "IAM-004-payment-service-data-access"
  scope       = var.subscription_scope
  description = "Least-privilege role for payment-service: read/write to payments_db.transactions only. No subscription-wide or storage-account-wide access."

  permissions {
    actions = [
      "Microsoft.DocumentDB/databaseAccounts/readonlyKeys/action",
    ]
    data_actions = [
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/replace",
    ]
    not_actions    = []
    not_data_actions = []
  }

  assignable_scopes = [var.payments_db_scope]
}

resource "azurerm_role_assignment" "payment_service_scoped" {
  scope              = var.payments_db_scope
  role_definition_id = azurerm_role_definition.payment_data_access.role_definition_resource_id
  principal_id       = azuread_service_principal.payment_service.object_id
}

# --- Phase 4 (Zero Trust, RR-02): account-service's role -----------------
# The service principal above has existed since Phase 1 with no role
# attached — this is what actually closes that gap, scoped to the Key
# Vault resource itself (which already exists, unlike payment-service's
# still-pending database resource above).

resource "azurerm_role_definition" "account_service_secrets_access" {
  name        = "IAM-004-account-service-secrets-access"
  scope       = var.subscription_scope
  description = "Least-privilege role for account-service: read secrets from key-vault only. No subscription-wide or resource-group-wide access."

  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/secrets/getSecret/action",
      "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
    ]
    not_actions       = []
    not_data_actions  = []
  }

  assignable_scopes = [var.account_service_secrets_scope]
}

resource "azurerm_role_assignment" "account_service_scoped" {
  scope              = var.account_service_secrets_scope
  role_definition_id = azurerm_role_definition.account_service_secrets_access.role_definition_resource_id
  principal_id       = azuread_service_principal.account_service.object_id
}

resource "azurerm_role_definition" "security_auditor" {
  name        = "security-auditor-readonly"
  scope       = var.subscription_scope
  description = "Read-only visibility across logs, policy compliance and security findings for the AI security agent and human auditors. Cannot modify or delete anything."

  permissions {
    actions = [
      "Microsoft.Insights/*/read",
      "Microsoft.Security/*/read",
      "Microsoft.PolicyInsights/*/read",
      "Microsoft.Authorization/*/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
    not_actions       = []
    data_actions      = []
    not_data_actions  = []
  }

  assignable_scopes = [var.subscription_scope]
}
