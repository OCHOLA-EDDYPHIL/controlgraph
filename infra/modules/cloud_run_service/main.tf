locals {
  service_contract = {
    project_id        = var.project_id
    region            = var.region
    service_name      = var.service_name
    container_image   = var.container_image
    minimum_instances = var.minimum_instances
    maximum_instances = var.maximum_instances
    resources_created = false
  }
}

check "scaling_bounds" {
  assert {
    condition     = var.minimum_instances <= var.maximum_instances
    error_message = "minimum_instances cannot exceed maximum_instances."
  }
}
