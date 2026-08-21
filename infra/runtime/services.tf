module "issuer" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.issuer
  description     = "Private ControlGraph capability issuer."
  container_image = var.controller_image
  service_account = local.service_accounts.issuer
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "issuer" })
  environment = merge(local.common_environment, local.identity_environment.issuer, {
    CONTROLGRAPH_ROLE                   = "issuer"
    CONTROLGRAPH_SERVICE_NAME           = local.service_names.issuer
    CONTROLGRAPH_CONTROLLER_ID          = "${var.project_id}:${var.region}:issuer"
    CONTROLGRAPH_CAPABILITY_KEY_VERSION = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION   = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_SIGNING_ALGORITHM      = data.terraform_remote_state.foundation.outputs.signing_keys.capability.algorithm
    CONTROLGRAPH_RECOVERY_URL           = local.service_audiences.recovery
  })
}

module "executor" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.executor
  description     = "Private target-bound ControlGraph canary executor."
  container_image = var.controller_image
  service_account = local.service_accounts.executor
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "executor" })
  environment = merge(local.common_environment, local.identity_environment.executor, {
    CONTROLGRAPH_ROLE                           = "executor"
    CONTROLGRAPH_SERVICE_NAME                   = local.service_names.executor
    CONTROLGRAPH_CONTROLLER_ID                  = "${var.project_id}:${var.region}:executor"
    CONTROLGRAPH_MUTATIONS_ENABLED              = "true"
    CONTROLGRAPH_CAPABILITY_KEY_VERSION         = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION           = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_COORDINATOR_URL                = local.service_audiences.coordinator
    CONTROLGRAPH_TARGET_NETWORK_RESOURCE        = data.terraform_remote_state.foundation.outputs.network.network_id
    CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE     = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
    CONTROLGRAPH_RECOVERY_FACADE_CALLER_EMAIL   = local.service_accounts.recovery
    CONTROLGRAPH_RECOVERY_FACADE_CALLER_SUBJECT = tostring(local.service_subjects.recovery)
  })
}

module "recovery" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.recovery
  description     = "Private stable-only ControlGraph recovery worker."
  container_image = var.controller_image
  service_account = local.service_accounts.recovery
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "recovery" })
  environment = merge(local.common_environment, local.identity_environment.recovery, {
    CONTROLGRAPH_ROLE                   = "recovery"
    CONTROLGRAPH_SERVICE_NAME           = local.service_names.recovery
    CONTROLGRAPH_CONTROLLER_ID          = "${var.project_id}:${var.region}:recovery"
    CONTROLGRAPH_MUTATIONS_ENABLED      = "true"
    CONTROLGRAPH_CAPABILITY_KEY_VERSION = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION   = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_EXECUTOR_URL           = local.service_audiences.executor
  })
}

module "verifier" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.verifier
  description     = "Private ControlGraph evidence verifier."
  container_image = var.controller_image
  service_account = local.service_accounts.verifier
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "verifier" })
  environment = merge(local.common_environment, local.identity_environment.verifier, {
    CONTROLGRAPH_ROLE                       = "verifier"
    CONTROLGRAPH_SERVICE_NAME               = local.service_names.verifier
    CONTROLGRAPH_CONTROLLER_ID              = "${var.project_id}:${var.region}:verifier"
    CONTROLGRAPH_CAPABILITY_KEY_VERSION     = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION       = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_EVIDENCE_WRITER_URL        = local.service_audiences.evidence_writer
    CONTROLGRAPH_TARGET_NETWORK_RESOURCE    = data.terraform_remote_state.foundation.outputs.network.network_id
    CONTROLGRAPH_TARGET_SUBNETWORK_RESOURCE = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  })
}

module "evidence_writer" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.evidence_writer
  description     = "Private ControlGraph evidence signer."
  container_image = var.controller_image
  service_account = local.service_accounts.evidence_writer
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "evidence-writer" })
  environment = merge(local.common_environment, local.identity_environment.evidence_writer, {
    CONTROLGRAPH_ROLE                                   = "evidence_writer"
    CONTROLGRAPH_SERVICE_NAME                           = local.service_names.evidence_writer
    CONTROLGRAPH_CONTROLLER_ID                          = "${var.project_id}:${var.region}:evidence_writer"
    CONTROLGRAPH_EVIDENCE_KEY_VERSION                   = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_SIGNING_ALGORITHM                      = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.algorithm
    CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_EMAIL   = local.service_accounts.verifier
    CONTROLGRAPH_CLASSIFICATION_EVIDENCE_CALLER_SUBJECT = tostring(local.service_subjects.verifier)
  })
}

module "coordinator" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.coordinator
  description     = "Private ControlGraph rollout coordinator."
  container_image = var.controller_image
  service_account = local.service_accounts.coordinator
  ingress         = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "coordinator" })
  environment = merge(local.common_environment, local.identity_environment.coordinator, {
    CONTROLGRAPH_ROLE                                    = "coordinator"
    CONTROLGRAPH_SERVICE_NAME                            = local.service_names.coordinator
    CONTROLGRAPH_CONTROLLER_ID                           = "${var.project_id}:${var.region}:coordinator"
    CONTROLGRAPH_ISSUER_URL                              = local.service_audiences.issuer
    CONTROLGRAPH_VERIFIER_URL                            = local.service_audiences.verifier
    CONTROLGRAPH_EVIDENCE_WRITER_URL                     = local.service_audiences.evidence_writer
    CONTROLGRAPH_CAPABILITY_KEY_VERSION                  = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION                    = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
    CONTROLGRAPH_CANDIDATE_REVISION_CONFIGURATION_SHA256 = var.reference_target_candidate_configuration_sha256
    CONTROLGRAPH_OPERATOR_EMAIL                          = local.runtime_identity_emails.operator
    CONTROLGRAPH_OPERATOR_SUBJECT                        = local.runtime_identity_subjects.operator
    CONTROLGRAPH_EXECUTOR_URL                            = local.service_audiences.executor
    CONTROLGRAPH_RECOVERY_URL                            = local.service_audiences.recovery
    CONTROLGRAPH_EXECUTION_QUEUE                         = local.execution_queue.name
    CONTROLGRAPH_RECOVERY_QUEUE                          = local.recovery_queue.name
    CONTROLGRAPH_EXECUTION_TASK_CALLER                   = local.service_accounts.execution_task_caller
    CONTROLGRAPH_RECOVERY_TASK_CALLER                    = local.service_accounts.recovery_task_caller
    CONTROLGRAPH_RECEIPT_AUTH_CALLER_EMAIL               = local.service_accounts.executor
    CONTROLGRAPH_RECEIPT_AUTH_CALLER_SUBJECT             = tostring(local.service_subjects.executor)
    CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_EMAIL      = local.service_accounts.executor
    CONTROLGRAPH_RECOVERY_RECEIPT_AUTH_CALLER_SUBJECT    = tostring(local.service_subjects.executor)
  })
}

module "api" {
  source = "../modules/cloud_run_service"

  depends_on = [google_artifact_registry_repository_iam_member.cloud_run_image_reader]

  project_id      = var.project_id
  region          = var.region
  service_name    = local.service_names.api
  description     = "Authenticated ControlGraph operator API."
  container_image = var.controller_image
  service_account = local.service_accounts.api
  ingress         = "INGRESS_TRAFFIC_ALL"
  network         = data.terraform_remote_state.foundation.outputs.network.network_id
  subnetwork      = data.terraform_remote_state.foundation.outputs.network.subnetwork_id
  vpc_egress      = "ALL_TRAFFIC"
  labels          = merge(local.common_labels, { component = "api" })
  environment = merge(local.common_environment, local.identity_environment.api, {
    CONTROLGRAPH_ROLE                           = "api"
    CONTROLGRAPH_SERVICE_NAME                   = local.service_names.api
    CONTROLGRAPH_CONTROLLER_ID                  = "${var.project_id}:${var.region}:api"
    CONTROLGRAPH_COORDINATOR_URL                = local.service_audiences.coordinator
    CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE = var.operator_oauth_client_audience
    CONTROLGRAPH_CAPABILITY_KEY_VERSION         = data.terraform_remote_state.foundation.outputs.signing_keys.capability.version
    CONTROLGRAPH_EVIDENCE_KEY_VERSION           = data.terraform_remote_state.foundation.outputs.signing_keys.evidence.version
  })
}
