resource "google_project_service_identity" "cloud_run" {
  provider = google-beta
  project  = var.project_id
  service  = "run.googleapis.com"
}

resource "google_project_service_identity" "cloud_tasks" {
  provider = google-beta
  project  = var.project_id
  service  = "cloudtasks.googleapis.com"
}

resource "google_artifact_registry_repository_iam_member" "cloud_run_image_reader" {
  project    = var.project_id
  location   = var.region
  repository = data.terraform_remote_state.foundation.outputs.artifact_repository.repository_id
  role       = "roles/artifactregistry.reader"
  member     = google_project_service_identity.cloud_run.member
}

resource "google_cloud_tasks_queue_iam_member" "coordinator_enqueuer" {
  for_each = {
    execution = google_cloud_tasks_queue.execution.name
    recovery  = google_cloud_tasks_queue.recovery.name
  }

  project  = var.project_id
  location = var.region
  name     = each.value
  role     = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.tasks_enqueuer
  member   = "serviceAccount:${local.service_accounts.coordinator}"
}

resource "google_service_account_iam_member" "coordinator_task_caller_actor" {
  for_each = toset([
    "execution_task_caller",
    "recovery_task_caller",
  ])

  service_account_id = data.terraform_remote_state.foundation.outputs.service_account_names[each.value]
  role               = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.task_oidc_actor
  member             = "serviceAccount:${local.service_accounts.coordinator}"
}

resource "google_service_account_iam_member" "cloud_tasks_token_creator" {
  for_each = toset([
    "execution_task_caller",
    "recovery_task_caller",
  ])

  service_account_id = data.terraform_remote_state.foundation.outputs.service_account_names[each.value]
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_project_service_identity.cloud_tasks.member
}

locals {
  run_invokers = {
    api = {
      service = module.api.service.name
      member  = var.operator_principal
    }
    coordinator = {
      service = module.coordinator.service.name
      member  = "serviceAccount:${local.service_accounts.api}"
    }
    issuer = {
      service = module.issuer.service.name
      member  = "serviceAccount:${local.service_accounts.coordinator}"
    }
    executor = {
      service = module.executor.service.name
      member  = "serviceAccount:${local.service_accounts.execution_task_caller}"
    }
    recovery = {
      service = module.recovery.service.name
      member  = "serviceAccount:${local.service_accounts.recovery_task_caller}"
    }
    verifier = {
      service = module.verifier.service.name
      member  = "serviceAccount:${local.service_accounts.coordinator}"
    }
    reference = {
      service = module.reference_target.target.name
      member  = "serviceAccount:${local.service_accounts.verifier}"
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  for_each = local.run_invokers

  project  = var.project_id
  location = var.region
  name     = each.value.service
  role     = "roles/run.invoker"
  member   = each.value.member
}
