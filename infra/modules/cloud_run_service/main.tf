resource "google_cloud_run_v2_service" "service" {
  project              = var.project_id
  location             = var.region
  name                 = var.service_name
  description          = var.description
  ingress              = var.ingress
  invoker_iam_disabled = false
  deletion_protection  = true
  labels               = var.labels

  template {
    service_account                  = var.service_account
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = var.timeout
    max_instance_request_concurrency = var.concurrency
    labels                           = var.labels

    scaling {
      min_instance_count = var.minimum_instances
      max_instance_count = var.maximum_instances
    }

    containers {
      name  = "controller"
      image = var.container_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = var.environment

        content {
          name  = env.key
          value = env.value
        }
      }

      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 5
        failure_threshold     = 12

        http_get {
          path = "/healthz"
          port = 8080
        }
      }

      liveness_probe {
        initial_delay_seconds = 5
        timeout_seconds       = 2
        period_seconds        = 10
        failure_threshold     = 3

        http_get {
          path = "/healthz"
          port = 8080
        }
      }
    }

    vpc_access {
      egress = var.vpc_egress

      network_interfaces {
        network    = var.network
        subnetwork = var.subnetwork
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    prevent_destroy = true
  }
}

check "scaling_bounds" {
  assert {
    condition     = var.minimum_instances <= var.maximum_instances
    error_message = "minimum_instances cannot exceed maximum_instances."
  }
}
