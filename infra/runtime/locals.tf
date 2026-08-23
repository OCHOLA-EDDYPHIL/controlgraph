locals {
  service_accounts     = data.terraform_remote_state.foundation.outputs.service_account_emails
  service_subjects     = data.terraform_remote_state.foundation.outputs.service_account_subjects
  project_number       = tostring(data.terraform_remote_state.foundation.outputs.project_number)
  console_service_name = "controlgraph-console"
  service_names = {
    api             = "controlgraph-api"
    coordinator     = "controlgraph-coordinator"
    issuer          = "controlgraph-issuer"
    executor        = "controlgraph-executor"
    recovery        = "controlgraph-recovery"
    verifier        = "controlgraph-verifier"
    evidence_writer = "controlgraph-evidence-writer"
  }

  controller_digest = regex("sha256:([0-9a-f]{64})$", var.controller_image)[0]

  common_labels = {
    application = "controlgraph"
    environment = "nonprod"
    lifecycle   = "retained"
    managed_by  = "terraform"
  }

  common_environment = {
    CONTROLGRAPH_PROJECT_ID         = var.project_id
    CONTROLGRAPH_PROJECT_NUMBER     = local.project_number
    CONTROLGRAPH_REGION             = var.region
    CONTROLGRAPH_BUILD_DIGEST       = "sha256:${local.controller_digest}"
    CONTROLGRAPH_CONTRACT_VERSION   = "controlgraph.contract/v1"
    CONTROLGRAPH_FIRESTORE_DATABASE = data.terraform_remote_state.foundation.outputs.firestore_authority.database_id
    CONTROLGRAPH_MUTATIONS_ENABLED  = "false"
    CONTROLGRAPH_ENVIRONMENT        = "nonprod"
  }

  service_audiences = {
    for role, service_name in local.service_names :
    role => "https://${service_name}-${local.project_number}.${var.region}.run.app"
  }
  console_origin = "https://${local.console_service_name}-${local.project_number}.${var.region}.run.app"

  runtime_identity_emails = {
    operator              = trimprefix(var.operator_principal, "user:")
    security_auditor      = local.service_accounts.security_auditor
    restricted_exporter   = local.service_accounts.restricted_exporter
    api                   = local.service_accounts.api
    coordinator           = local.service_accounts.coordinator
    issuer                = local.service_accounts.issuer
    executor              = local.service_accounts.executor
    recovery              = local.service_accounts.recovery
    verifier              = local.service_accounts.verifier
    evidence_writer       = local.service_accounts.evidence_writer
    execution_task_caller = local.service_accounts.execution_task_caller
    recovery_task_caller  = local.service_accounts.recovery_task_caller
    retention_sweeper     = local.service_accounts.retention_sweeper
  }

  runtime_identity_subjects = {
    operator              = var.operator_subject
    security_auditor      = tostring(local.service_subjects.security_auditor)
    restricted_exporter   = tostring(local.service_subjects.restricted_exporter)
    api                   = tostring(local.service_subjects.api)
    coordinator           = tostring(local.service_subjects.coordinator)
    issuer                = tostring(local.service_subjects.issuer)
    executor              = tostring(local.service_subjects.executor)
    recovery              = tostring(local.service_subjects.recovery)
    verifier              = tostring(local.service_subjects.verifier)
    evidence_writer       = tostring(local.service_subjects.evidence_writer)
    execution_task_caller = tostring(local.service_subjects.execution_task_caller)
    recovery_task_caller  = tostring(local.service_subjects.recovery_task_caller)
    retention_sweeper     = tostring(local.service_subjects.retention_sweeper)
  }

  route_caller_roles = {
    api             = "operator"
    coordinator     = "api"
    issuer          = "coordinator"
    executor        = "execution_task_caller"
    recovery        = "recovery_task_caller"
    verifier        = "coordinator"
    evidence_writer = "coordinator"
  }

  identity_environment = {
    for service_role, caller_role in local.route_caller_roles : service_role => {
      CONTROLGRAPH_AUTH_AUDIENCE       = local.service_audiences[service_role]
      CONTROLGRAPH_AUTH_CALLER_ROLE    = caller_role
      CONTROLGRAPH_AUTH_CALLER_EMAIL   = local.runtime_identity_emails[caller_role]
      CONTROLGRAPH_AUTH_CALLER_SUBJECT = local.runtime_identity_subjects[caller_role]
    }
  }

  execution_queue = {
    name         = "controlgraph-execution"
    handler_path = "/v1/internal/tasks/execute"
    fixed_query  = "controlgraph_route=execution"
    role         = "executor"
    caller       = "execution_task_caller"
  }

  recovery_queue = {
    name         = "controlgraph-recovery"
    handler_path = "/v1/internal/tasks/recover"
    fixed_query  = "controlgraph_route=recovery"
    role         = "recovery"
    caller       = "recovery_task_caller"
  }
}

check "runtime_identity_map_is_closed" {
  assert {
    condition = (
      toset(keys(local.runtime_identity_emails)) == toset([
        "operator",
        "security_auditor",
        "restricted_exporter",
        "api",
        "coordinator",
        "issuer",
        "executor",
        "recovery",
        "verifier",
        "evidence_writer",
        "execution_task_caller",
        "recovery_task_caller",
        "retention_sweeper",
      ]) &&
      toset(keys(local.runtime_identity_subjects)) == toset(keys(local.runtime_identity_emails)) &&
      toset(keys(local.route_caller_roles)) == toset(keys(local.service_names))
    )
    error_message = "Runtime identity and protected-route caller maps must remain complete and closed."
  }
}

check "timeline_reader_identities_are_separated" {
  assert {
    condition = length(toset([
      "${local.runtime_identity_emails.operator}:${local.runtime_identity_subjects.operator}",
      "${local.runtime_identity_emails.security_auditor}:${local.runtime_identity_subjects.security_auditor}",
      "${local.runtime_identity_emails.restricted_exporter}:${local.runtime_identity_subjects.restricted_exporter}",
    ])) == 3
    error_message = "Operator, security-audit, and restricted-export identities must be distinct."
  }
}

check "evidence_writer_route_is_fixed" {
  assert {
    condition = (
      local.service_names.evidence_writer == "controlgraph-evidence-writer" &&
      local.route_caller_roles.evidence_writer == "coordinator" &&
      local.identity_environment.evidence_writer.CONTROLGRAPH_AUTH_AUDIENCE == local.service_audiences.evidence_writer &&
      local.identity_environment.evidence_writer.CONTROLGRAPH_AUTH_CALLER_EMAIL == local.service_accounts.coordinator &&
      local.identity_environment.evidence_writer.CONTROLGRAPH_AUTH_CALLER_SUBJECT == tostring(local.service_subjects.coordinator)
    )
    error_message = "The evidence-writer route must remain bound to its fixed audience and coordinator identity."
  }
}

check "task_route_overrides_are_fixed" {
  assert {
    condition = (
      local.execution_queue.fixed_query == "controlgraph_route=execution" &&
      local.recovery_queue.fixed_query == "controlgraph_route=recovery" &&
      local.execution_queue.fixed_query != local.recovery_queue.fixed_query
    )
    error_message = "Task queues must replace caller-supplied queries with distinct fixed routes."
  }
}
