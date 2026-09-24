# Secrets module — Cloud KMS key ring/key for CMEK, and a Secret Manager
# secret as the equivalent of Azure Key Vault. Secret Manager access is
# IAM-only by design (there's no network-ACL concept to disable here, so
# the control that matters is who gets a binding — which nobody gets by
# default in this module).

resource "google_kms_key_ring" "this" {
  name     = "kr-${var.project_name}-${var.environment}"
  location = var.region
}

resource "google_kms_crypto_key" "this" {
  name            = "cmek-${var.project_name}-${var.environment}"
  key_ring        = google_kms_key_ring.this.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret" "app_secrets" {
  secret_id = "${var.project_name}-app-secrets-${var.environment}"

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.this.id
        }
      }
    }
  }
}

# Phase 4 (Zero Trust, RR-02) — account-service's ONLY grant, scoped to
# this one secret, mirroring modules/storage's
# payment_service_scoped_access pattern for payment-service's bucket.
resource "google_secret_manager_secret_iam_member" "account_service_scoped_access" {
  secret_id = google_secret_manager_secret.app_secrets.secret_id
  role      = var.account_service_secrets_access_role_id
  member    = "serviceAccount:${var.account_service_account_email}"
}
