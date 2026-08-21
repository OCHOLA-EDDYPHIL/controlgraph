locals {
  monitoring_health_readers = toset(["verifier"])
}

resource "google_project_iam_member" "monitoring_health_reader" {
  for_each = local.monitoring_health_readers

  project = var.project_id
  role    = google_project_iam_custom_role.controlgraph["monitoring_health_reader"].name
  member  = google_service_account.workloads[each.value].member
}

check "monitoring_health_reader_is_project_scoped_to_verifier" {
  assert {
    condition = (
      local.monitoring_health_readers == toset(["verifier"]) &&
      toset(keys(google_project_iam_member.monitoring_health_reader)) == toset(["verifier"]) &&
      alltrue([
        for identity, binding in google_project_iam_member.monitoring_health_reader :
        identity == "verifier" &&
        binding.project == var.project_id &&
        binding.role == google_project_iam_custom_role.controlgraph["monitoring_health_reader"].name &&
        binding.member == google_service_account.workloads["verifier"].member &&
        length(binding.condition) == 0
      ])
    )
    error_message = "The Monitoring health reader role must be bound at project scope only to the verifier service account."
  }
}
