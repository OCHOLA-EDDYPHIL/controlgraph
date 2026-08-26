locals {
  operational_log_alerts = {
    stale_denial = {
      display_name = "ControlGraph stale authority denial"
      severity     = "WARNING"
      owner        = "operator"
      resource     = "cloud_run_revision"
      runbook      = "stale-denial-and-manual-epoch-revocation"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"stale_denial\"",
      ])
    }
    ambiguous_mutation = {
      display_name = "ControlGraph ambiguous mutation"
      severity     = "ERROR"
      owner        = "operator"
      resource     = "cloud_run_revision"
      runbook      = "ambiguous-mutation-readback"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"ambiguous_mutation\"",
      ])
    }
    stuck_task = {
      display_name = "ControlGraph stuck task"
      severity     = "ERROR"
      owner        = "operator"
      resource     = "cloud_tasks_queue"
      runbook      = "queue-drain"
      filter = join(" AND ", [
        "resource.type=\"cloud_tasks_queue\"",
        "resource.labels.queue_id=(\"controlgraph-execution\" OR \"controlgraph-recovery\")",
        "jsonPayload.@type=\"type.googleapis.com/google.cloud.tasks.logging.v1.TaskActivityLog\"",
        "jsonPayload.attemptResponseLog:*",
        "(jsonPayload.attemptResponseLog.status!=\"OK\" OR jsonPayload.attemptResponseLog.dispatchCount>=\"3\")",
      ])
    }
    unhealthy_rollout = {
      display_name = "ControlGraph unhealthy rollout"
      severity     = "WARNING"
      owner        = "operator"
      resource     = "cloud_run_revision"
      runbook      = "stable-recovery"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"unhealthy_rollout\"",
      ])
    }
    failed_recovery = {
      display_name = "ControlGraph failed stable recovery"
      severity     = "CRITICAL"
      owner        = "operator"
      resource     = "cloud_run_revision"
      runbook      = "stable-recovery"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"failed_recovery\"",
      ])
    }
    key_problem = {
      display_name = "ControlGraph signing key problem"
      severity     = "CRITICAL"
      owner        = "security-audit"
      resource     = "global"
      runbook      = "key-rotation-or-disablement"
      filter = join(" AND ", [
        "resource.type=\"cloudkms_cryptokeyversion\"",
        "resource.labels.key_ring_id=\"controlgraph-signing\"",
        "protoPayload.serviceName=\"cloudkms.googleapis.com\"",
        "(protoPayload.status.code>0 OR protoPayload.methodName=\"google.cloud.kms.v1.KeyManagementService.UpdateCryptoKeyVersion\" OR protoPayload.methodName=\"google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion\")",
      ])
    }
    verifier_disagreement = {
      display_name = "ControlGraph verifier disagreement"
      severity     = "ERROR"
      owner        = "security-audit"
      resource     = "cloud_run_revision"
      runbook      = "verifier-disagreement-or-evidence-failure"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"verifier_disagreement\"",
      ])
    }
    evidence_failure = {
      display_name = "ControlGraph evidence failure"
      severity     = "ERROR"
      owner        = "security-audit"
      resource     = "cloud_run_revision"
      runbook      = "verifier-disagreement-or-evidence-failure"
      filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"controlgraph-coordinator\"",
        "jsonPayload.event=\"controlgraph.operational.signal\"",
        "jsonPayload.signal=\"evidence_failure\"",
      ])
    }
  }
}

resource "google_logging_metric" "operational" {
  for_each = local.operational_log_alerts

  project     = var.project_id
  name        = "controlgraph_${each.key}_total"
  description = "Count of ${each.value.display_name} log signals."
  filter      = each.value.filter

  metric_descriptor {
    display_name = each.value.display_name
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
  }

  depends_on = [google_project_service.required["logging.googleapis.com"]]
}

resource "google_monitoring_notification_channel" "operator_email" {
  project      = var.project_id
  display_name = "ControlGraph operator"
  description  = "Incident open and recovery notifications for the explicit ControlGraph operator."
  type         = "email"
  enabled      = true
  labels = {
    email_address = trimprefix(var.operator_principal, "user:")
  }
  user_labels = {
    application = "controlgraph"
    owner       = "operator"
  }

  depends_on = [google_project_service.required["monitoring.googleapis.com"]]
}

resource "google_monitoring_alert_policy" "operational" {
  for_each = local.operational_log_alerts

  project      = var.project_id
  display_name = each.value.display_name
  combiner     = "OR"
  enabled      = true
  severity     = each.value.severity

  conditions {
    display_name = "At least one ${each.key} signal in 60 seconds"

    condition_threshold {
      filter = join(" AND ", [
        try(each.value.resource_filter, "resource.type=\"${each.value.resource}\""),
        "metric.type=\"logging.googleapis.com/user/${google_logging_metric.operational[each.key].name}\"",
      ])
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    subject   = "${each.value.severity}: ${each.value.display_name}"
    content   = "Owner: ${each.value.owner}. Threshold: one matching signal in 60 seconds. Use the matched log's root digest and epoch, or provider resource, to correlate evidence. The incident sends both open and recovery notifications."

    links {
      display_name = "Runbook"
      url          = "https://github.com/OCHOLA-EDDYPHIL/controlgraph/blob/main/docs/runbooks.md#${each.value.runbook}"
    }

    links {
      display_name = "Logs Explorer"
      url          = "https://console.cloud.google.com/logs/query?project=${var.project_id}"
    }
  }

  notification_channels = [google_monitoring_notification_channel.operator_email.name]

  alert_strategy {
    auto_close           = "1800s"
    notification_prompts = ["OPENED", "CLOSED"]

    notification_channel_strategy {
      notification_channel_names = [google_monitoring_notification_channel.operator_email.name]
      renotify_interval          = "1800s"
    }
  }

  user_labels = {
    application = "controlgraph"
    component   = "operations"
    owner       = each.value.owner
    signal      = replace(each.key, "_", "-")
  }
}

check "operational_alert_set_is_closed" {
  assert {
    condition = (
      toset(keys(local.operational_log_alerts)) == toset([
        "ambiguous_mutation",
        "evidence_failure",
        "failed_recovery",
        "key_problem",
        "stale_denial",
        "stuck_task",
        "unhealthy_rollout",
        "verifier_disagreement",
      ]) &&
      alltrue([
        for alert in google_monitoring_alert_policy.operational :
        alert.notification_channels == [google_monitoring_notification_channel.operator_email.name]
      ])
    )
    error_message = "Operational alerts must cover the fixed signal set and notify only the explicit operator channel."
  }
}
