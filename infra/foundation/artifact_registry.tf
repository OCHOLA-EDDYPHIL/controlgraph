resource "google_artifact_registry_repository" "images" {
  project       = var.project_id
  location      = var.region
  repository_id = var.artifact_repository_id
  description   = "Immutable ControlGraph Canary container images"
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"
  labels        = local.common_labels

  docker_config {
    immutable_tags = true
  }

  cleanup_policies {
    id     = "delete-untagged-after-seven-days"
    action = "DELETE"

    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s"
    }
  }

  cleanup_policy_dry_run = false

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["artifactregistry.googleapis.com"]]
}
