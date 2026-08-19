output "controller_services" {
  description = "Private controller service coordinates keyed by role."
  value = {
    api         = module.api.service
    coordinator = module.coordinator.service
    issuer      = module.issuer.service
    executor    = module.executor.service
    recovery    = module.recovery.service
    verifier    = module.verifier.service
  }
}

output "task_queues" {
  description = "Fixed addressed Cloud Tasks delivery routes and bounds."
  value = {
    execution = {
      id                    = google_cloud_tasks_queue.execution.id
      handler               = "${module.executor.service.uri}${local.execution_queue.handler_path}"
      audience              = module.executor.service.uri
      caller                = local.service_accounts.execution_task_caller
      max_dispatches_second = 1
      max_concurrency       = 1
      max_attempts          = 3
      max_retry_duration    = "900s"
    }
    recovery = {
      id                    = google_cloud_tasks_queue.recovery.id
      handler               = "${module.recovery.service.uri}${local.recovery_queue.handler_path}"
      audience              = module.recovery.service.uri
      caller                = local.service_accounts.recovery_task_caller
      max_dispatches_second = 1
      max_concurrency       = 1
      max_attempts          = 3
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
