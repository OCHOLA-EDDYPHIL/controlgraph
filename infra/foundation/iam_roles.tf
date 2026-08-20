locals {
  custom_iam_roles = {
    firestore_reader = {
      role_id     = "controlgraph.firestoreAuthorityReader"
      title       = "ControlGraph Firestore authority reader"
      description = "Read the exact ControlGraph authority database without mutation permissions."
      permissions = [
        "datastore.databases.get",
        "datastore.entities.get",
      ]
    }
    firestore_writer = {
      role_id     = "controlgraph.firestoreAuthorityWriter"
      title       = "ControlGraph Firestore authority writer"
      description = "Create and update authority records without deletion permissions."
      permissions = [
        "datastore.databases.get",
        "datastore.entities.create",
        "datastore.entities.get",
        "datastore.entities.update",
      ]
    }
    kms_version_reader = {
      role_id     = "controlgraph.kmsVersionReader"
      title       = "ControlGraph KMS version metadata reader"
      description = "Read the state and algorithm of an exact bound signing key version."
      permissions = [
        "cloudkms.cryptoKeyVersions.get",
      ]
    }
    tasks_enqueuer = {
      role_id     = "controlgraph.tasksEnqueuer"
      title       = "ControlGraph task enqueuer"
      description = "Inspect one bound queue and create addressed tasks in it."
      permissions = [
        "cloudtasks.queues.get",
        "cloudtasks.tasks.create",
      ]
    }
    tasks_controller = {
      role_id     = "controlgraph.tasksController"
      title       = "ControlGraph task controller"
      description = "Inspect, pause, or resume one bound queue without task execution or deletion."
      permissions = [
        "cloudtasks.queues.get",
        "cloudtasks.queues.pause",
        "cloudtasks.queues.resume",
      ]
    }
    task_oidc_actor = {
      role_id     = "controlgraph.taskOidcActor"
      title       = "ControlGraph task OIDC actor"
      description = "Attach one exact task-caller identity without token minting or impersonation."
      permissions = [
        "iam.serviceAccounts.actAs",
      ]
    }
    run_snapshot_reader = {
      role_id     = "controlgraph.runSnapshotReader"
      title       = "ControlGraph Cloud Run snapshot reader"
      description = "Read one bound service and its immutable revisions."
      permissions = [
        "run.revisions.get",
        "run.services.get",
      ]
    }
    run_traffic_mutator = {
      role_id     = "controlgraph.runTrafficMutator"
      title       = "ControlGraph Cloud Run traffic mutator"
      description = "Read and update one bound Cloud Run service."
      permissions = [
        "run.services.get",
        "run.services.update",
      ]
    }
    run_stable_restorer = {
      role_id     = "controlgraph.runStableRestorer"
      title       = "ControlGraph Cloud Run stable restorer"
      description = "Read and update one bound Cloud Run service through the restore-only recovery contract."
      permissions = [
        "run.services.get",
        "run.services.update",
      ]
    }
    run_operation_reader = {
      role_id     = "controlgraph.runOperationReader"
      title       = "ControlGraph Cloud Run operation reader"
      description = "Read the result of a Cloud Run control-plane operation."
      permissions = [
        "run.operations.get",
      ]
    }
    monitoring_health_reader = {
      role_id     = "controlgraph.monitoringHealthReader"
      title       = "ControlGraph Monitoring health reader"
      description = "List health time series in the dedicated ControlGraph project without metric mutation."
      permissions = [
        "monitoring.timeSeries.list",
      ]
    }
  }
}

resource "google_project_iam_custom_role" "controlgraph" {
  for_each = local.custom_iam_roles

  project     = var.project_id
  role_id     = each.value.role_id
  title       = each.value.title
  description = each.value.description
  permissions = each.value.permissions
  stage       = "GA"

  depends_on = [google_project_service.required]

  lifecycle {
    prevent_destroy = true
  }
}

check "run_snapshot_reader_is_get_only" {
  assert {
    condition = toset(local.custom_iam_roles.run_snapshot_reader.permissions) == toset([
      "run.revisions.get",
      "run.services.get",
    ])
    error_message = "The snapshot reader role must contain only exact Cloud Run get permissions."
  }
}

check "run_executor_roles_are_minimal" {
  assert {
    condition = (
      toset(local.custom_iam_roles.run_traffic_mutator.permissions) == toset([
        "run.services.get",
        "run.services.update",
      ]) &&
      toset(local.custom_iam_roles.run_operation_reader.permissions) == toset([
        "run.operations.get",
      ])
    )
    error_message = "The executor Cloud Run roles must contain only target read/update and operation-read permissions."
  }
}

check "run_recovery_roles_are_minimal" {
  assert {
    condition = (
      local.custom_iam_roles.run_stable_restorer.role_id != local.custom_iam_roles.run_traffic_mutator.role_id &&
      toset(local.custom_iam_roles.run_stable_restorer.permissions) == toset([
        "run.services.get",
        "run.services.update",
      ]) &&
      toset(local.custom_iam_roles.run_operation_reader.permissions) == toset([
        "run.operations.get",
      ])
    )
    error_message = "The recovery Cloud Run roles must remain distinct and contain only target read/update and operation-read permissions."
  }
}

check "monitoring_health_reader_is_read_only" {
  assert {
    condition = toset(local.custom_iam_roles.monitoring_health_reader.permissions) == toset([
      "monitoring.timeSeries.list",
    ])
    error_message = "The verifier Monitoring role must contain only time-series read permission."
  }
}

check "tasks_controller_is_queue_control_only" {
  assert {
    condition = toset(local.custom_iam_roles.tasks_controller.permissions) == toset([
      "cloudtasks.queues.get",
      "cloudtasks.queues.pause",
      "cloudtasks.queues.resume",
    ])
    error_message = "The task controller role must contain only queue inspect, pause, and resume permissions."
  }
}

output "custom_iam_role_names" {
  description = "Least-privilege ControlGraph custom-role names keyed by purpose."
  value       = { for purpose, role in google_project_iam_custom_role.controlgraph : purpose => role.name }
}
