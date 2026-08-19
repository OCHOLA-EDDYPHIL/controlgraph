locals {
  workload_service_accounts = {
    api = {
      account_id   = "controlgraph-api"
      display_name = "ControlGraph API"
      description  = "Authenticated operator API workload identity."
    }
    coordinator = {
      account_id   = "controlgraph-coordinator"
      display_name = "ControlGraph coordinator"
      description  = "Rollout coordination workload identity."
    }
    issuer = {
      account_id   = "controlgraph-issuer"
      display_name = "ControlGraph capability issuer"
      description  = "Capability issuance workload identity."
    }
    executor = {
      account_id   = "controlgraph-executor"
      display_name = "ControlGraph executor"
      description  = "Canary and promotion execution workload identity."
    }
    recovery = {
      account_id   = "controlgraph-recovery"
      display_name = "ControlGraph recovery"
      description  = "Stable-revision recovery workload identity."
    }
    verifier = {
      account_id   = "controlgraph-verifier"
      display_name = "ControlGraph verifier"
      description  = "Health and evidence verification workload identity."
    }
    evidence_writer = {
      account_id   = "cg-evidence-writer"
      display_name = "ControlGraph evidence writer"
      description  = "Append-only evidence signing workload identity with no authority-write permission."
    }
    reference = {
      account_id   = "controlgraph-reference"
      display_name = "ControlGraph reference target"
      description  = "Disposable reference target workload identity."
    }
    execution_task_caller = {
      account_id   = "cg-execution-task-caller"
      display_name = "ControlGraph execution task caller"
      description  = "OIDC caller identity for the execution queue."
    }
    recovery_task_caller = {
      account_id   = "cg-recovery-task-caller"
      display_name = "ControlGraph recovery task caller"
      description  = "OIDC caller identity for the recovery queue."
    }
    ci_image_builder = {
      account_id   = "cg-ci-image-builder"
      display_name = "ControlGraph CI image builder"
      description  = "Keyless CI identity for publishing reviewed images."
    }
    ci_terraform = {
      account_id   = "cg-ci-terraform"
      display_name = "ControlGraph CI Terraform"
      description  = "Keyless CI identity for reviewed Terraform operations."
    }
  }
}

resource "google_service_account" "workloads" {
  for_each = local.workload_service_accounts

  project      = var.project_id
  account_id   = each.value.account_id
  display_name = each.value.display_name
  description  = each.value.description

  depends_on = [google_project_service.required]

  lifecycle {
    prevent_destroy = true
  }
}

check "operator_is_an_explicit_human" {
  assert {
    condition     = startswith(var.operator_principal, "user:")
    error_message = "operator_principal must be one explicit user: principal, not a workload, group, or domain."
  }
}

output "service_account_emails" {
  description = "ControlGraph workload service-account emails keyed by role."
  value       = { for role, account in google_service_account.workloads : role => account.email }
}

output "service_account_names" {
  description = "ControlGraph workload service-account resource names keyed by role."
  value       = { for role, account in google_service_account.workloads : role => account.name }
}

output "service_account_subjects" {
  description = "Immutable Google identity subjects keyed by ControlGraph workload role."
  value       = { for role, account in google_service_account.workloads : role => account.unique_id }
}
