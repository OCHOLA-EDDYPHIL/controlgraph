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

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_logging_project_bucket_config" "controlgraph" {
  project          = var.project_id
  location         = var.region
  bucket_id        = "controlgraph-audit"
  description      = "Regional ControlGraph Canary audit and workload logs"
  retention_days   = 30
  enable_analytics = false

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["logging.googleapis.com"]]
}

# _Default is provider-created. The Google provider acquires and updates this
# reserved sink instead of attempting to create or delete it.
resource "google_logging_project_sink" "default" {
  project     = var.project_id
  name        = "_Default"
  description = "Route ControlGraph logs to the dedicated regional bucket."
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.controlgraph.bucket_id}"
  filter = join(" AND ", [
    "NOT LOG_ID(\"cloudaudit.googleapis.com/activity\")",
    "NOT LOG_ID(\"externalaudit.googleapis.com/activity\")",
    "NOT LOG_ID(\"cloudaudit.googleapis.com/system_event\")",
    "NOT LOG_ID(\"externalaudit.googleapis.com/system_event\")",
    "NOT LOG_ID(\"cloudaudit.googleapis.com/access_transparency\")",
    "NOT LOG_ID(\"externalaudit.googleapis.com/access_transparency\")",
  ])
  disabled               = false
  unique_writer_identity = true

  lifecycle {
    prevent_destroy = true
  }
}
