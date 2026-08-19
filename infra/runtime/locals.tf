locals {
  service_accounts = data.terraform_remote_state.foundation.outputs.service_account_emails
  service_names = {
    api         = "controlgraph-api"
    coordinator = "controlgraph-coordinator"
    issuer      = "controlgraph-issuer"
    executor    = "controlgraph-executor"
    recovery    = "controlgraph-recovery"
    verifier    = "controlgraph-verifier"
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
    CONTROLGRAPH_REGION             = var.region
    CONTROLGRAPH_BUILD_DIGEST       = "sha256:${local.controller_digest}"
    CONTROLGRAPH_CONTRACT_VERSION   = "controlgraph.contract/v1"
    CONTROLGRAPH_FIRESTORE_DATABASE = data.terraform_remote_state.foundation.outputs.firestore_authority.database_id
    CONTROLGRAPH_MUTATIONS_ENABLED  = "false"
    CONTROLGRAPH_ENVIRONMENT        = "nonprod"
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
