output "target" {
  description = "Fixed reference-target deployment, revision, traffic, and scaling definition."
  value = {
    id                      = google_cloud_run_v2_service.reference.id
    project_id              = var.project_id
    region                  = var.region
    name                    = google_cloud_run_v2_service.reference.name
    uri                     = google_cloud_run_v2_service.reference.uri
    generation              = google_cloud_run_v2_service.reference.generation
    etag                    = google_cloud_run_v2_service.reference.etag
    latest_created_revision = google_cloud_run_v2_service.reference.latest_created_revision
    latest_ready_revision   = google_cloud_run_v2_service.reference.latest_ready_revision
    stable_revision         = local.stable_revision
    candidate_revision      = local.candidate_revision
    stable_image            = var.stable_image
    candidate_image         = var.candidate_image
    deployment_phase        = var.deployment_phase
    service_account         = var.service_account
    ingress                 = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    minimum_instances       = 0
    maximum_instances       = 1
    baseline_traffic = {
      stable_percent    = 100
      candidate_percent = 0
    }
  }
}
