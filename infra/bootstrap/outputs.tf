output "project_id" {
  description = "Dedicated ControlGraph Canary project identifier."
  value       = google_project.controlgraph.project_id
}

output "project_number" {
  description = "Dedicated ControlGraph Canary project number."
  value       = google_project.controlgraph.number
}

output "region" {
  description = "Fixed region for regional ControlGraph resources."
  value       = var.region
}

output "state_bucket_name" {
  description = "Retained bucket used by ControlGraph Terraform stacks."
  value       = google_storage_bucket.terraform_state.name
}

output "organization_id" {
  description = "Organization that owns the dedicated project."
  value       = var.organization_id
}
