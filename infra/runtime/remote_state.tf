data "terraform_remote_state" "bootstrap" {
  backend = "gcs"

  config = {
    bucket = var.state_bucket_name
    prefix = var.bootstrap_state_prefix
  }
}

data "terraform_remote_state" "foundation" {
  backend = "gcs"

  config = {
    bucket = var.state_bucket_name
    prefix = var.foundation_state_prefix
  }
}

check "runtime_matches_bootstrap" {
  assert {
    condition = (
      data.terraform_remote_state.bootstrap.outputs.project_id == var.project_id &&
      data.terraform_remote_state.bootstrap.outputs.region == var.region &&
      data.terraform_remote_state.bootstrap.outputs.state_bucket_name == var.state_bucket_name &&
      var.state_bucket_name == "${var.project_id}-tfstate"
    )
    error_message = "Runtime project, region, and state bucket must match the isolated bootstrap state."
  }
}

check "runtime_matches_foundation" {
  assert {
    condition = (
      data.terraform_remote_state.foundation.outputs.project_id == var.project_id &&
      data.terraform_remote_state.foundation.outputs.region == var.region &&
      data.terraform_remote_state.foundation.outputs.state_bucket_name == var.state_bucket_name &&
      data.terraform_remote_state.foundation.outputs.operator_principal == var.operator_principal
    )
    error_message = "Runtime coordinates and operator must match the reviewed foundation state."
  }
}

check "controller_image_is_isolated" {
  assert {
    condition = startswith(
      var.controller_image,
      "${var.region}-docker.pkg.dev/${var.project_id}/${data.terraform_remote_state.foundation.outputs.artifact_repository.repository_id}/",
    )
    error_message = "controller_image must come from the dedicated regional ControlGraph repository."
  }
}

check "reference_target_images_are_isolated" {
  assert {
    condition = (
      startswith(
        var.reference_target_stable_image,
        "${var.region}-docker.pkg.dev/${var.project_id}/${data.terraform_remote_state.foundation.outputs.artifact_repository.repository_id}/",
      ) &&
      startswith(
        var.reference_target_candidate_image,
        "${var.region}-docker.pkg.dev/${var.project_id}/${data.terraform_remote_state.foundation.outputs.artifact_repository.repository_id}/",
      ) &&
      regex("sha256:([0-9a-f]{64})$", var.reference_target_stable_image)[0] !=
      regex("sha256:([0-9a-f]{64})$", var.reference_target_candidate_image)[0]
    )
    error_message = "Reference-target images must be distinct digests from the dedicated regional ControlGraph repository."
  }
}
