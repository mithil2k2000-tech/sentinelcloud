output "log_bucket_name" {
  value = google_storage_bucket.logs.name
}

output "sink_writer_identity" {
  value = google_logging_project_sink.audit.writer_identity
}
