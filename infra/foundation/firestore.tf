locals {
  firestore_database_id       = "controlgraph-authority"
  timeline_raw_collection     = "controlgraph_timeline_raw"
  timeline_raw_expiry_field   = "expires_at"
  timeline_raw_retention_days = 30

  firestore_readers = toset([
    "api",
    "issuer",
    "executor",
    "recovery",
    "verifier",
  ])
  firestore_writers = toset(["coordinator"])

  firestore_database_resource = "projects/${var.project_id}/databases/${local.firestore_database_id}"
  firestore_database_condition = join(" || ", [
    "resource.name == '${local.firestore_database_resource}'",
    "resource.name.startsWith('${local.firestore_database_resource}/documents/')",
  ])
}

check "timeline_raw_retention_is_bounded" {
  assert {
    condition = (
      local.timeline_raw_collection == "controlgraph_timeline_raw" &&
      local.timeline_raw_expiry_field == "expires_at" &&
      local.timeline_raw_retention_days == 30 &&
      contains(local.firestore_readers, "api") &&
      !contains(local.firestore_writers, "api")
    )
    error_message = "Raw timeline evidence must use its fixed 30-day TTL field and read-only API access."
  }
}

check "coordinator_is_the_only_firestore_writer" {
  assert {
    condition = (
      local.firestore_writers == toset(["coordinator"]) &&
      length(setintersection(local.firestore_readers, local.firestore_writers)) == 0
    )
    error_message = "Only the coordinator authority facade may hold database write permission."
  }
}

resource "google_firestore_database" "authority" {
  project                           = var.project_id
  name                              = local.firestore_database_id
  location_id                       = var.region
  type                              = "FIRESTORE_NATIVE"
  database_edition                  = "STANDARD"
  concurrency_mode                  = "PESSIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_DISABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [
    google_project_service.required["firestore.googleapis.com"],
    google_project_service.required["datastore.googleapis.com"],
  ]
}

resource "google_project_iam_member" "firestore_reader" {
  for_each = local.firestore_readers

  project = var.project_id
  role    = google_project_iam_custom_role.controlgraph["firestore_reader"].name
  member  = google_service_account.workloads[each.value].member

  condition {
    title       = "controlgraph_authority_database"
    description = "Read only the named ControlGraph authority database and its documents."
    expression  = local.firestore_database_condition
  }

  depends_on = [google_firestore_database.authority]
}

resource "google_project_iam_member" "firestore_coordinator_writer" {
  for_each = local.firestore_writers

  project = var.project_id
  role    = google_project_iam_custom_role.controlgraph["firestore_writer"].name
  member  = google_service_account.workloads[each.value].member

  condition {
    title       = "controlgraph_coordinator_authority_database"
    description = "Write the authority database only through the coordinator facade."
    expression  = local.firestore_database_condition
  }

  depends_on = [google_firestore_database.authority]
}

resource "google_firestore_field" "timeline_raw_expiry" {
  project    = var.project_id
  database   = google_firestore_database.authority.name
  collection = local.timeline_raw_collection
  field      = local.timeline_raw_expiry_field

  ttl_config {}

  index_config {}

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_firestore_database.authority]
}
