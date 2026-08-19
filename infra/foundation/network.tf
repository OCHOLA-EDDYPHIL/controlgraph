resource "google_compute_network" "controlgraph" {
  project                         = var.project_id
  name                            = var.network_name
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  mtu                             = 1460
  delete_default_routes_on_create = false

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "controlgraph" {
  project                  = var.project_id
  region                   = var.region
  name                     = var.subnetwork_name
  network                  = google_compute_network.controlgraph.id
  ip_cidr_range            = var.subnetwork_cidr
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"

  lifecycle {
    prevent_destroy = true
  }
}
