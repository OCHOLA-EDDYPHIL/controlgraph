output "service" {
  description = "Bounded Cloud Run service coordinates and observed concurrency token."
  value = {
    id                    = google_cloud_run_v2_service.service.id
    name                  = google_cloud_run_v2_service.service.name
    uri                   = google_cloud_run_v2_service.service.uri
    latest_ready_revision = google_cloud_run_v2_service.service.latest_ready_revision
    generation            = google_cloud_run_v2_service.service.generation
    etag                  = google_cloud_run_v2_service.service.etag
    ingress               = google_cloud_run_v2_service.service.ingress
    service_account       = var.service_account
  }
}
