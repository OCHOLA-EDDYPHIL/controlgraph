resource "google_cloud_scheduler_job" "timeline_retention" {
  project          = var.project_id
  region           = var.region
  name             = "controlgraph-timeline-retention"
  description      = "Run the bounded raw-evidence retention sweep."
  schedule         = "*/5 * * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"

  retry_config {
    retry_count          = 3
    max_retry_duration   = "300s"
    min_backoff_duration = "5s"
    max_backoff_duration = "30s"
    max_doublings        = 2
  }

  http_target {
    http_method = "POST"
    uri         = "${local.service_audiences.coordinator}/v1/internal/timeline/retention"

    oidc_token {
      service_account_email = local.service_accounts.retention_sweeper
      audience              = local.service_audiences.coordinator
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_cloud_run_v2_service_iam_member.invoker["coordinator_retention"],
    google_service_account_iam_member.cloud_scheduler_token_creator,
  ]
}

check "timeline_retention_schedule_is_fixed" {
  assert {
    condition = (
      google_cloud_scheduler_job.timeline_retention.schedule == "*/5 * * * *" &&
      google_cloud_scheduler_job.timeline_retention.time_zone == "Etc/UTC" &&
      google_cloud_scheduler_job.timeline_retention.attempt_deadline == "60s" &&
      google_cloud_scheduler_job.timeline_retention.retry_config[0].retry_count == 3 &&
      google_cloud_scheduler_job.timeline_retention.http_target[0].uri == "${local.service_audiences.coordinator}/v1/internal/timeline/retention" &&
      google_cloud_scheduler_job.timeline_retention.http_target[0].oidc_token[0].service_account_email == local.service_accounts.retention_sweeper &&
      google_cloud_scheduler_job.timeline_retention.http_target[0].oidc_token[0].audience == local.service_audiences.coordinator
    )
    error_message = "Timeline retention must remain a fixed five-minute POST from the sweeper identity to the coordinator."
  }
}
