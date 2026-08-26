locals {
  service_name       = "controlgraph-reference-target"
  stable_revision    = "controlgraph-reference-target-stable-v6"
  candidate_revision = "controlgraph-reference-target-candidate-v6"
  active_revision    = var.deployment_phase == "stable" ? local.stable_revision : local.candidate_revision
  active_image       = var.deployment_phase == "stable" ? var.stable_image : var.candidate_image
  labels = {
    application = "controlgraph"
    component   = "reference-target"
    environment = "nonprod"
    lifecycle   = "retained"
    managed_by  = "terraform"
  }
}

resource "google_cloud_run_v2_service" "reference" {
  project              = var.project_id
  location             = var.region
  name                 = local.service_name
  description          = "Private disposable ControlGraph reference target."
  ingress              = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  invoker_iam_disabled = false
  deletion_protection  = true
  labels               = local.labels

  scaling {
    min_instance_count = 0
  }

  template {
    revision                         = local.active_revision
    service_account                  = var.service_account
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "5s"
    max_instance_request_concurrency = 8
    labels                           = local.labels

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      name  = "reference-target"
      image = local.active_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
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
      egress = "ALL_TRAFFIC"

      network_interfaces {
        network    = var.network
        subnetwork = var.subnetwork
      }
    }
  }

  traffic {
    type     = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
    revision = local.stable_revision
    percent  = 100
    tag      = "stable"
  }

  dynamic "traffic" {
    for_each = var.deployment_phase == "candidate" ? toset([local.candidate_revision]) : toset([])

    content {
      type     = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
      revision = traffic.value
      percent  = 0
      tag      = "candidate"
    }
  }

  lifecycle {
    prevent_destroy = true

    # Creation establishes the safe 100/0 baseline. Subsequent traffic belongs
    # to the epoch-fenced controller while Terraform retains every other field.
    ignore_changes = [traffic]
  }
}

check "reference_target_coordinates_are_fixed" {
  assert {
    condition = (
      can(regex("^controlgraph-canary-[a-z0-9]{6,10}$", var.project_id)) &&
      var.region == "us-central1" &&
      var.service_account == "controlgraph-reference@${var.project_id}.iam.gserviceaccount.com"
    )
    error_message = "The reference target must use the dedicated project, us-central1, and fixed reference identity."
  }
}

check "reference_target_baseline_is_bounded" {
  assert {
    condition = (
      google_cloud_run_v2_service.reference.template[0].scaling[0].min_instance_count == 0 &&
      google_cloud_run_v2_service.reference.template[0].scaling[0].max_instance_count == 1 &&
      google_cloud_run_v2_service.reference.ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY"
    )
    error_message = "The reference target must remain private and bounded from zero to one instance."
  }
}
