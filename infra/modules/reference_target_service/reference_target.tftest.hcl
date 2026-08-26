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

run "stable_revision_starts_at_the_bounded_baseline" {
  command = plan

  variables {
    deployment_phase = "stable"
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.name == "controlgraph-reference-target" &&
      google_cloud_run_v2_service.reference.ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" &&
      google_cloud_run_v2_service.reference.template[0].revision == "controlgraph-reference-target-stable-v5" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].image == var.stable_image
    )
    error_message = "The stable deployment must remain target-bound to its fixed private revision and image."
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].scaling[0].min_instance_count == 0 &&
      google_cloud_run_v2_service.reference.template[0].scaling[0].max_instance_count == 1 &&
      google_cloud_run_v2_service.reference.scaling[0].min_instance_count == 0 &&
      length(google_cloud_run_v2_service.reference.traffic) == 1 &&
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-stable-v5" &&
        target.percent == 100 && target.tag == "stable"
      ]) == 1
    )
    error_message = "The stable deployment must scale from zero to one and route 100 percent to stable."
  }

  assert {
    condition = (
      output.target.baseline_reset.project_id == var.project_id &&
      output.target.baseline_reset.region == "us-central1" &&
      output.target.baseline_reset.service_name == "controlgraph-reference-target" &&
      output.target.baseline_reset.stable_revision == "controlgraph-reference-target-stable-v5" &&
      output.target.baseline_reset.candidate_revision == "controlgraph-reference-target-candidate-v5" &&
      output.target.baseline_reset.stable_image == var.stable_image &&
      output.target.baseline_reset.candidate_image == var.candidate_image &&
      output.target.baseline_reset.network_resource == var.network &&
      output.target.baseline_reset.subnetwork_resource == var.subnetwork &&
      output.target.baseline_reset.concurrency == 8 &&
      output.target.baseline_reset.stable_percent == 100 &&
      output.target.baseline_reset.candidate_percent == 0 &&
      output.target.baseline_reset.confirmation == "RESET_REFERENCE_TARGET_BASELINE"
    )
    error_message = "The explicit baseline-reset inputs must remain fixed to the deployed reference target."
  }
}

run "candidate_configuration_shape_is_bounded" {
  command = plan

  variables {
    deployment_phase = "candidate"
  }

  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].revision == "controlgraph-reference-target-candidate-v5" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].image == var.candidate_image &&
      google_cloud_run_v2_service.reference.template[0].execution_environment == "EXECUTION_ENVIRONMENT_GEN2" &&
      google_cloud_run_v2_service.reference.template[0].containers[0].resources[0].limits["memory"] == "512Mi" &&
      length(google_cloud_run_v2_service.reference.traffic) == 2
    )
    error_message = "The candidate deployment must create the fixed Gen2 candidate revision from its immutable image and supported memory bound."
  }

  assert {
    condition = (
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-stable-v5" &&
        target.percent == 100 && target.tag == "stable"
      ]) == 1 &&
      length([
        for target in google_cloud_run_v2_service.reference.traffic : target
        if target.revision == "controlgraph-reference-target-candidate-v5" &&
        target.percent == 0 && target.tag == "candidate"
      ]) == 1
    )
    error_message = "The static candidate configuration must declare 100-percent stable and zero-percent candidate traffic."
  }
}

run "matching_image_digests_are_rejected" {
  command = plan

  variables {
    deployment_phase = "stable"
    candidate_image  = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-canary/reference-candidate@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.candidate_image]
}

run "candidate_repository_substitution_is_rejected" {
  command = plan

  variables {
    deployment_phase = "candidate"
    candidate_image  = "us-central1-docker.pkg.dev/controlgraph-canary-abc123/other/reference-candidate@sha256:2222222222222222222222222222222222222222222222222222222222222222"
  }

  expect_failures = [var.candidate_image]
}
