# Storage module — the GCS equivalent of Azure's storage module: closed by
# default, opened only for the one workload that needs it, at the one
# resource it needs.

resource "google_storage_bucket" "customer_data" {
  name     = "${var.project_name}-customer-data-${var.environment}-${var.project_id}"
  location = var.region

  uniform_bucket_level_access = true # disables ACLs — IAM only, no per-object public grants
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = var.kms_key_id
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "AbortIncompleteMultipartUpload"
    }
  }
}

# payment-service gets object-level access to this ONE bucket via the
# IAM-004 custom role from modules/iam — nothing project-wide, and never a
# built-in roles/owner, roles/editor, or roles/storage.admin.
resource "google_storage_bucket_iam_member" "payment_service_scoped_access" {
  bucket = google_storage_bucket.customer_data.name
  role   = var.payment_data_access_role_id
  member = "serviceAccount:${var.payment_service_account_email}"
}
