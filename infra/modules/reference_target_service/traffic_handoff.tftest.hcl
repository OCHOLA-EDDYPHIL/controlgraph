mock_provider "google" {}

variables {
  project_id      = "controlgraph-canary-abc123"
  region          = "us-central1"
  service_account = "controlgraph-reference@controlgraph-canary-abc123.iam.gserviceaccount.com"
  stable_image    = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-canary/reference-stable@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  candidate_image = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-canary/reference-candidate@sha256:2222222222222222222222222222222222222222222222222222222222222222"
  network         = "projects/controlgraph-canary-abc123/global/networks/controlgraph"
  subnetwork      = "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/controlgraph"
}

run "create_safe_stable_baseline" {
  command = apply

  variables {
    deployment_phase = "stable"
  }

  assert {
    condition = (
      length(google_cloud_run_v2_service.reference.traffic) == 1 &&
      google_cloud_run_v2_service.reference.traffic[0].revision == "controlgraph-reference-target-stable-v20" &&
      google_cloud_run_v2_service.reference.traffic[0].percent == 100
    )
    error_message = "Initial creation must establish the explicit 100-percent stable baseline."
  }
}

run "stage_candidate_without_reclaiming_traffic" {
  command = apply

  variables {
    deployment_phase = "candidate"
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].revision == "controlgraph-reference-target-candidate-v20" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].image == var.candidate_image &&
      length(google_cloud_run_v2_service.reference.traffic) == 1 &&
      google_cloud_run_v2_service.reference.traffic[0].revision == "controlgraph-reference-target-stable-v20" &&
      google_cloud_run_v2_service.reference.traffic[0].percent == 100
    )
    error_message = "Candidate revision staging must leave the previously established traffic untouched."
  }
}
