output "project_id" {
  description = "Dedicated project validated against bootstrap state."
  value       = var.project_id
}

output "project_number" {
  description = "Dedicated project number validated against bootstrap state."
  value       = var.project_number
}

output "region" {
  description = "Sole regional boundary for managed resources."
  value       = var.region
}

output "state_bucket_name" {
  description = "ControlGraph-only Terraform state bucket."
  value       = var.state_bucket_name
}

output "foundation_state_prefix" {
  description = "GCS prefix to use when initializing the foundation backend."
  value       = "foundation"
}

output "required_services" {
  description = "Google Cloud services retained for the ControlGraph environment."
  value       = sort(tolist(local.required_services))
}

output "network" {
  description = "Dedicated regional network coordinates for runtime stacks."
  value = {
    network_id        = google_compute_network.controlgraph.id
    network_name      = google_compute_network.controlgraph.name
    subnetwork_id     = google_compute_subnetwork.controlgraph.id
    subnetwork_name   = google_compute_subnetwork.controlgraph.name
    subnetwork_cidr   = google_compute_subnetwork.controlgraph.ip_cidr_range
    subnetwork_region = google_compute_subnetwork.controlgraph.region
  }
}

output "artifact_repository" {
  description = "Regional immutable-tag Docker repository coordinates."
  value = {
    id            = google_artifact_registry_repository.images.id
    repository_id = google_artifact_registry_repository.images.repository_id
    location      = google_artifact_registry_repository.images.location
  }
}

output "audit_log_bucket" {
  description = "Dedicated regional log bucket that receives the project _Default sink."
  value = {
    id             = google_logging_project_bucket_config.controlgraph.id
    location       = google_logging_project_bucket_config.controlgraph.location
    retention_days = google_logging_project_bucket_config.controlgraph.retention_days
    sink           = google_logging_project_sink.default.name
  }
}
