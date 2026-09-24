# Logging module — Phase 9 (SIEM + Detection), v1 spec §16.
#
# GCP emits Cloud Audit Logs by default, but Admin Activity/Data Access/
# Data Write logs are only as useful as their retention and export — this
# wires a project-wide log sink into a dedicated, locked-down, versioned
# GCS bucket for long-term centralized storage, and turns on Data Access
# audit logging (off by default, since it's high-volume). This is the
# concrete infrastructure behind flipping architecture-hardened-gcp.json's
# "logging.enabled" from false to true, and it's what closes RR-01 in
# threat-model/residual-risk-register.md.

resource "google_storage_bucket" "logs" {
  name                        = "${var.project_name}-${var.environment}-audit-logs-${var.project_id}"
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false
  public_access_prevention    = "enforced"
  labels                      = var.labels

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = var.log_retention_days
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_logging_project_sink" "audit" {
  name        = "${var.project_name}-${var.environment}-audit-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.logs.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""

  # GCP creates a dedicated service account for this sink; granting IT
  # write access (below) rather than the caller's own identity is what
  # makes this a real least-privilege delivery path, not an ambient one.
  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit.writer_identity
}

# Data Access logs (who read/wrote what, not just who changed config) are
# off by default in GCP because of volume/cost — turning them on for every
# service is the direct GCP equivalent of Azure's "allLogs" diagnostic
# category and AWS CloudTrail's data-event selector above.
resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
