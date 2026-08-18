output "controller_contract" {
  description = "Validated future Cloud Run service contract; no resource is created."
  value       = module.controller_service_contract.contract
}
