resource "google_cloud_tasks_queue" "execution" {
  project  = var.project_id
  location = var.region
  name     = local.execution_queue.name

  rate_limits {
    max_dispatches_per_second = 1
    max_concurrent_dispatches = 1
  }

  retry_config {
    # Eight bounded deliveries span the executor's 60-second orphan grace while
    # preserving a 45-second acceptance reserve before permit expiry.
    max_attempts       = 8
    max_retry_duration = "900s"
    min_backoff        = "5s"
    max_backoff        = "10s"
    max_doublings      = 3
  }

  http_target {
    http_method = "POST"

    header_overrides {
      header {
        key   = "Content-Type"
        value = "application/json"
      }
    }

    uri_override {
      scheme                    = "HTTPS"
      host                      = trimprefix(local.service_audiences.executor, "https://")
      uri_override_enforce_mode = "ALWAYS"

      path_override {
        path = local.execution_queue.handler_path
      }

      query_override {
        query_params = local.execution_queue.fixed_query
      }
    }

    oidc_token {
      service_account_email = local.service_accounts.execution_task_caller
      audience              = local.service_audiences.executor
    }
  }

  stackdriver_logging_config {
    sampling_ratio = 1
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_service_account_iam_member.cloud_tasks_token_creator,
    google_service_account_iam_member.coordinator_task_caller_actor,
  ]
}

resource "google_cloud_tasks_queue" "recovery" {
  project  = var.project_id
  location = var.region
  name     = local.recovery_queue.name

  rate_limits {
    max_dispatches_per_second = 1
    max_concurrent_dispatches = 1
  }

  retry_config {
    # Keep recovery delivery geometry identical to execution delivery geometry.
    max_attempts       = 8
    max_retry_duration = "900s"
    min_backoff        = "5s"
    max_backoff        = "10s"
    max_doublings      = 3
  }

  http_target {
    http_method = "POST"

    header_overrides {
      header {
        key   = "Content-Type"
        value = "application/json"
      }
    }

    uri_override {
      scheme                    = "HTTPS"
      host                      = trimprefix(local.service_audiences.recovery, "https://")
      uri_override_enforce_mode = "ALWAYS"

      path_override {
        path = local.recovery_queue.handler_path
      }

      query_override {
        query_params = local.recovery_queue.fixed_query
      }
    }

    oidc_token {
      service_account_email = local.service_accounts.recovery_task_caller
      audience              = local.service_audiences.recovery
    }
  }

  stackdriver_logging_config {
    sampling_ratio = 1
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_service_account_iam_member.cloud_tasks_token_creator,
    google_service_account_iam_member.coordinator_task_caller_actor,
  ]
}
