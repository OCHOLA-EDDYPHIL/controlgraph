resource "google_storage_bucket_iam_member" "ci_terraform_state" {
  bucket = var.state_bucket_name
  role   = "roles/storage.objectAdmin"
  member = google_service_account.workloads["ci_terraform"].member
}

resource "google_artifact_registry_repository_iam_member" "ci_image_writer" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.workloads["ci_image_builder"].member
}

resource "google_service_account_iam_member" "github_ci_impersonation" {
  for_each = toset([
    "ci_image_builder",
    "ci_terraform",
  ])

  service_account_id = google_service_account.workloads[each.value].name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.github_wif_principal_sets[each.value]
}
