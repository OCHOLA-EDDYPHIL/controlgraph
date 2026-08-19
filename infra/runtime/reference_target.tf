module "reference_target" {
  source = "../modules/reference_target_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id       = var.project_id
  region           = var.region
  service_account  = local.service_accounts.reference
  stable_image     = var.reference_target_stable_image
  candidate_image  = var.reference_target_candidate_image
  deployment_phase = var.reference_target_deployment_phase
  network          = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork       = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
}
