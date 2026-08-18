module "controller_service_contract" {
  source = "./modules/cloud_run_service"

  project_id        = var.project_id
  region            = var.region
  service_name      = var.service_name
  container_image   = var.controller_image
  minimum_instances = var.minimum_instances
  maximum_instances = var.maximum_instances
}
