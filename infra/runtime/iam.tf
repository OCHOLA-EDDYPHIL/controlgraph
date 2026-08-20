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

resource "google_cloud_tasks_queue_iam_member" "operator_execution_controller" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_tasks_queue.execution.name
  role     = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.tasks_controller
  member   = var.operator_principal
}

check "operator_queue_control_is_execution_only" {
  assert {
    condition = (
      google_cloud_tasks_queue_iam_member.operator_execution_controller.project == var.project_id &&
      google_cloud_tasks_queue_iam_member.operator_execution_controller.location == var.region &&
      google_cloud_tasks_queue_iam_member.operator_execution_controller.name == google_cloud_tasks_queue.execution.id &&
      google_cloud_tasks_queue_iam_member.operator_execution_controller.role == data.terraform_remote_state.foundation.outputs.custom_iam_role_names.tasks_controller &&
      google_cloud_tasks_queue_iam_member.operator_execution_controller.member == var.operator_principal
    )
    error_message = "Operator queue control must remain bound only to controlgraph-execution in us-central1."
  }
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

resource "google_service_account_iam_member" "executor_reference_target_act_as" {
  service_account_id = data.terraform_remote_state.foundation.outputs.service_account_names.reference
  role               = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.task_oidc_actor
  member             = "serviceAccount:${local.service_accounts.executor}"
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
    coordinator_receipts = {
      service = module.coordinator.service.name
      member  = "serviceAccount:${local.service_accounts.executor}"
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
    evidence_writer = {
      service = module.evidence_writer.service.name
      member  = "serviceAccount:${local.service_accounts.coordinator}"
    }
    evidence_writer_verifier = {
      service = module.evidence_writer.service.name
      member  = "serviceAccount:${local.service_accounts.verifier}"
    }
    reference = {
      service = module.reference_target.target.name
      member  = "serviceAccount:${local.service_accounts.verifier}"
    }
  }
}

check "runtime_invoker_map_is_closed" {
  assert {
    condition = (
      toset(keys(local.run_invokers)) == toset([
        "api",
        "coordinator",
        "coordinator_receipts",
        "issuer",
        "executor",
        "recovery",
        "verifier",
        "evidence_writer",
        "evidence_writer_verifier",
        "reference",
      ]) &&
      local.run_invokers.coordinator_receipts.service == module.coordinator.service.name &&
      local.run_invokers.coordinator_receipts.member == "serviceAccount:${local.service_accounts.executor}" &&
      local.run_invokers.evidence_writer.service == module.evidence_writer.service.name &&
      local.run_invokers.evidence_writer.member == "serviceAccount:${local.service_accounts.coordinator}" &&
      local.run_invokers.evidence_writer_verifier.service == module.evidence_writer.service.name &&
      local.run_invokers.evidence_writer_verifier.member == "serviceAccount:${local.service_accounts.verifier}"
    )
    error_message = "Runtime invocation must remain closed and evidence-writer callers must remain coordinator and verifier only."
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

resource "google_cloud_run_v2_service_iam_member" "verifier_target_snapshot" {
  project  = var.project_id
  location = var.region
  name     = module.reference_target.target.name
  role     = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.run_snapshot_reader
  member   = "serviceAccount:${local.service_accounts.verifier}"
}

resource "google_cloud_run_v2_service_iam_member" "executor_target_traffic_mutator" {
  project  = var.project_id
  location = var.region
  name     = module.reference_target.target.name
  role     = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.run_traffic_mutator
  member   = "serviceAccount:${local.service_accounts.executor}"
}

resource "google_project_iam_member" "executor_operation_reader" {
  project = var.project_id
  role    = data.terraform_remote_state.foundation.outputs.custom_iam_role_names.run_operation_reader
  member  = "serviceAccount:${local.service_accounts.executor}"

  condition {
    title       = "controlgraph_executor_us_central1_operations"
    description = "Read only Cloud Run operation status in the fixed runtime region."
    expression  = "resource.name.startsWith('projects/${var.project_id}/locations/${var.region}/operations/')"
  }
}

check "verifier_snapshot_reader_is_service_scoped" {
  assert {
    condition = (
      google_cloud_run_v2_service_iam_member.verifier_target_snapshot.project == var.project_id &&
      google_cloud_run_v2_service_iam_member.verifier_target_snapshot.location == var.region &&
      google_cloud_run_v2_service_iam_member.verifier_target_snapshot.name == module.reference_target.target.name &&
      google_cloud_run_v2_service_iam_member.verifier_target_snapshot.member == "serviceAccount:${local.service_accounts.verifier}"
    )
    error_message = "The verifier snapshot role must remain bound only on the fixed reference service."
  }
}

check "executor_target_mutation_is_service_scoped" {
  assert {
    condition = (
      google_cloud_run_v2_service_iam_member.executor_target_traffic_mutator.project == var.project_id &&
      google_cloud_run_v2_service_iam_member.executor_target_traffic_mutator.location == var.region &&
      google_cloud_run_v2_service_iam_member.executor_target_traffic_mutator.name == module.reference_target.target.name &&
      google_cloud_run_v2_service_iam_member.executor_target_traffic_mutator.role == data.terraform_remote_state.foundation.outputs.custom_iam_role_names.run_traffic_mutator &&
      google_cloud_run_v2_service_iam_member.executor_target_traffic_mutator.member == "serviceAccount:${local.service_accounts.executor}" &&
      data.terraform_remote_state.foundation.outputs.service_account_names.reference == "projects/${var.project_id}/serviceAccounts/controlgraph-reference@${var.project_id}.iam.gserviceaccount.com" &&
      data.terraform_remote_state.foundation.outputs.custom_iam_role_names.task_oidc_actor == "projects/${var.project_id}/roles/controlgraph.taskOidcActor" &&
      google_service_account_iam_member.executor_reference_target_act_as.service_account_id == data.terraform_remote_state.foundation.outputs.service_account_names.reference &&
      google_service_account_iam_member.executor_reference_target_act_as.role == data.terraform_remote_state.foundation.outputs.custom_iam_role_names.task_oidc_actor &&
      google_service_account_iam_member.executor_reference_target_act_as.member == "serviceAccount:controlgraph-executor@${var.project_id}.iam.gserviceaccount.com" &&
      google_project_iam_member.executor_operation_reader.project == var.project_id &&
      google_project_iam_member.executor_operation_reader.role == data.terraform_remote_state.foundation.outputs.custom_iam_role_names.run_operation_reader &&
      google_project_iam_member.executor_operation_reader.member == "serviceAccount:${local.service_accounts.executor}" &&
      google_project_iam_member.executor_operation_reader.condition[0].expression == "resource.name.startsWith('projects/${var.project_id}/locations/${var.region}/operations/')"
    )
    error_message = "The executor may mutate only the fixed reference service, act as only its fixed runtime identity, and read operation status only in the fixed project region."
  }
}
