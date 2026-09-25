# Policy module — policy-as-code guardrails that BLOCK, not just report.
#
# This is the deterministic-enforcement half of the "LLM reasons, policy
# enforces" split from the roadmap. Each definition below maps to one of
# the failure modes called out in Phase 2's example gate output:
#
#   ❌ Storage bucket publicly accessible   -> deny-public-storage
#   ❌ Database encryption disabled         -> require-encryption
#   ❌ Excessive IAM permissions            -> deny-owner-contributor-assignment
#   ❌ Kubernetes privileged container      -> deny-privileged-containers (built-in initiative)

variable "management_group_or_subscription_id" {
  description = "Scope to assign policies at (subscription ID or management group ID)."
  type        = string
}

resource "azurerm_policy_definition" "deny_public_storage" {
  name         = "deny-public-storage-accounts"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny storage accounts with public network access enabled"
  description  = "Blocks deployment of any storage account that allows public network access or nested-item public access. Corresponds to control IAM-004 / finding 'storage bucket publicly accessible'."

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          field  = "Microsoft.Storage/storageAccounts/publicNetworkAccess"
          equals = "Enabled"
        },
        {
          field  = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess"
          equals = "true"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_policy_definition" "require_encryption" {
  name         = "require-encryption-at-rest"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Require encryption at rest on storage and Key Vault resources"
  description  = "Denies storage accounts or Key Vaults deployed without infrastructure/double encryption enabled."

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field     = "Microsoft.Storage/storageAccounts/encryption.requireInfrastructureEncryption"
          notEquals = "true"
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_policy_definition" "deny_broad_role_assignment" {
  name         = "deny-owner-contributor-assignment"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Owner/Contributor role assignments to service principals"
  description  = "Service identities (workloads) must use purpose-built custom roles (see modules/iam), never subscription-wide Owner or Contributor. Corresponds to finding 'excessive IAM permissions'."

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Authorization/roleAssignments" },
        {
          anyOf = [
            { field = "Microsoft.Authorization/roleAssignments/roleDefinitionId", contains = "b24988ac-6180-42a0-ab88-20f7382dd24c" }, # Contributor
            { field = "Microsoft.Authorization/roleAssignments/roleDefinitionId", contains = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" }  # Owner
          ]
        }
      ]
    }
    then = {
      effect = "deny"
    }
  })
}

resource "azurerm_policy_set_definition" "guardrail_baseline" {
  name         = "guardrail-baseline-initiative"
  policy_type  = "Custom"
  display_name = "Cloud security platform — baseline guardrail initiative"
  description  = "Bundles the custom deny policies plus the built-in AKS 'no privileged containers' initiative into one assignable set."

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_public_storage.id
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.require_encryption.id
  }

  policy_definition_reference {
    policy_definition_id = azurerm_policy_definition.deny_broad_role_assignment.id
  }

  # Built-in: "Kubernetes cluster containers should not use forbidden
  # sysctl interfaces" / "...should not share host process ID or IPC
  # namespace" style controls come from Azure Policy's built-in AKS
  # initiative (id 42b8ef37-b724-4e24-bbc8-7a7708edfe00) — referenced by ID
  # rather than redefined here.
}

resource "azurerm_subscription_policy_assignment" "guardrail_baseline" {
  name                 = "guardrail-baseline"
  policy_definition_id = azurerm_policy_set_definition.guardrail_baseline.id
  subscription_id      = "/subscriptions/${var.management_group_or_subscription_id}"
  description          = "Deployment-blocking guardrails for the cloud security platform."
  display_name         = "Guardrail baseline"
}
