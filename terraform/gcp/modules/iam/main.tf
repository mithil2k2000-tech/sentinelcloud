# IAM module — one service account per workload, custom least-privilege
# roles bound at the specific resource, never at project level. Mirrors
# terraform/azure/modules/iam's IAM-004 pattern exactly, so the two clouds
# are comparable in the threat model.

resource "google_service_account" "payment_service" {
  account_id   = "${var.project_name}-payment-svc-${var.environment}"
  display_name = "payment-service workload identity"
}

resource "google_service_account" "account_service" {
  account_id   = "${var.project_name}-account-svc-${var.environment}"
  display_name = "account-service workload identity"
}

# Custom role: read/write to exactly the payments data, nothing else.
# Bound to the storage bucket resource itself in modules/storage (see
# google_storage_bucket_iam_member there) — NOT at project scope, and
# never roles/owner or roles/editor.
resource "google_project_iam_custom_role" "payment_data_access" {
  role_id     = "${replace(var.project_name, "-", "_")}_payment_data_access_${var.environment}"
  project     = var.project_id
  title       = "IAM-004 payment-service data access"
  description = "Least-privilege role for payment-service: object read/write on the payments bucket only. No project-wide access."
  permissions = [
    "storage.objects.get",
    "storage.objects.create",
    "storage.objects.list",
  ]
}

# Phase 4 (Zero Trust, RR-02): account-service's own identity had existed
# since Phase 1 with no role attached — this custom role + the binding in
# modules/secrets (scoped to the one secret, not the whole project) is
# what actually closes that gap, matching payment-service's pattern.
resource "google_project_iam_custom_role" "account_service_secrets_access" {
  role_id     = "${replace(var.project_name, "-", "_")}_account_secrets_access_${var.environment}"
  project     = var.project_id
  title       = "IAM-004 account-service secrets access"
  description = "Least-privilege role for account-service: read access to the app secret only. No project-wide access."
  permissions = [
    "secretmanager.versions.access",
    "secretmanager.secrets.get",
  ]
}

resource "google_project_iam_custom_role" "security_auditor" {
  role_id     = "${replace(var.project_name, "-", "_")}_security_auditor_${var.environment}"
  project     = var.project_id
  title       = "Security auditor (read-only)"
  description = "Read-only visibility across logging, IAM policy, and org policy compliance for the AI security agent and human auditors."
  permissions = [
    "logging.logEntries.list",
    "logging.sinks.list",
    "resourcemanager.projects.getIamPolicy",
    "orgpolicy.policy.get",
    "compute.firewalls.list",
  ]
}
