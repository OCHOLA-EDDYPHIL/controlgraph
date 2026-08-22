output "controller_services" {
  description = "Private controller service coordinates keyed by role."
  value = {
    api             = module.api.service
    coordinator     = module.coordinator.service
    issuer          = module.issuer.service
    executor        = module.executor.service
    recovery        = module.recovery.service
    verifier        = module.verifier.service
    evidence_writer = module.evidence_writer.service
  }
}

output "operator_console" {
  description = "Public static console host and its fixed private operator API origin."
  value = {
    service    = module.console.service
    origin     = local.console_origin
    api_origin = local.service_audiences.api
    image      = var.console_image
  }
}

output "task_queues" {
  description = "Fixed addressed Cloud Tasks delivery routes and bounds."
  value = {
    execution = {
      id                    = google_cloud_tasks_queue.execution.id
      handler               = "${local.service_audiences.executor}${local.execution_queue.handler_path}"
      audience              = local.service_audiences.executor
      caller                = local.service_accounts.execution_task_caller
      max_dispatches_second = 1
      max_concurrency       = 1
      max_attempts          = 6
      max_retry_duration    = "900s"
    }
    recovery = {
      id                    = google_cloud_tasks_queue.recovery.id
      handler               = "${local.service_audiences.recovery}${local.recovery_queue.handler_path}"
      audience              = local.service_audiences.recovery
      caller                = local.service_accounts.recovery_task_caller
      max_dispatches_second = 1
      max_concurrency       = 1
      max_attempts          = 6
      max_retry_duration    = "900s"
    }
  }
}

output "runtime_image" {
  description = "Immutable controller image used by every private service shell."
  value       = var.controller_image
}

output "reference_target" {
  description = "Private disposable target and its exact stable baseline reset definition."
  value       = module.reference_target.target
}
