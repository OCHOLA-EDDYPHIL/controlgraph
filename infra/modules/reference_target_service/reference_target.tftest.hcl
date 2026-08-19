mock_provider "google" {}

variables {
  project_id      = "controlgraph-canary-abc123"
  region          = "us-central1"
  service_account = "controlgraph-reference@controlgraph-canary-abc123.iam.gserviceaccount.com"
  stable_image    = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-images/reference-stable@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  candidate_image = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-images/reference-candidate@sha256:2222222222222222222222222222222222222222222222222222222222222222"
  network         = "projects/controlgraph-canary-abc123/global/networks/controlgraph"
  subnetwork      = "projects/controlgraph-canary-abc123/regions/us-central1/subnetworks/controlgraph"
}

run "stable_revision_starts_at_the_bounded_baseline" {
  command = plan

  variables {
    deployment_phase = "stable"
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.name == "controlgraph-reference-target" &&
      google_cloud_run_v2_service.reference.ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" &&
      google_cloud_run_v2_service.reference.template[0].revision == "controlgraph-reference-target-stable-v1" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].image == var.stable_image
    )
    error_message = "The stable deployment must remain target-bound to its fixed private revision and image."
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].scaling[0].min_instance_count == 0 &&
      google_cloud_run_v2_service.reference.template[0].scaling[0].max_instance_count == 1 &&
      length(google_cloud_run_v2_service.reference.traffic) == 1 &&
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-stable-v1" &&
        target.percent == 100 && target.tag == "stable"
      ]) == 1
    )
    error_message = "The stable deployment must scale from zero to one and route 100 percent to stable."
  }
}

run "candidate_revision_preserves_the_explicit_stable_reset" {
  command = plan

  variables {
    deployment_phase = "candidate"
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].revision == "controlgraph-reference-target-candidate-v1" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].image == var.candidate_image &&
      length(google_cloud_run_v2_service.reference.traffic) == 2
    )
    error_message = "The candidate deployment must create the fixed candidate revision from its immutable image."
  }

  assert {
    condition = (
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-stable-v1" &&
        target.percent == 100 && target.tag == "stable"
      ]) == 1 &&
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-candidate-v1" &&
        target.percent == 0 && target.tag == "candidate"
      ]) == 1
    )
    error_message = "The candidate phase must retain the explicit 100-percent stable, zero-percent candidate reset."
  }
}

run "matching_image_digests_are_rejected" {
  command = plan

  variables {
    deployment_phase = "stable"
    candidate_image  = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-images/a-different-name@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [check.reference_target_images_are_distinct_and_immutable]
}
