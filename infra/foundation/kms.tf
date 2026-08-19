locals {
  signing_key_purposes = {
    capability = {
      name        = "capability-signing"
      description = "Signs bounded ControlGraph capability envelopes."
    }
    evidence = {
      name        = "evidence-signing"
      description = "Signs ControlGraph receipts and acceptance evidence."
    }
  }

  capability_version_readers = toset([
    "api",
    "executor",
    "issuer",
    "recovery",
    "verifier",
  ])

  evidence_version_readers = toset([
    "api",
    "evidence_writer",
  ])
}

check "exactly_two_signing_purposes" {
  assert {
    condition     = toset(keys(local.signing_key_purposes)) == toset(["capability", "evidence"])
    error_message = "ControlGraph must provision exactly the capability and evidence signing keys."
  }
}

resource "google_kms_key_ring" "controlgraph" {
  project  = var.project_id
  location = var.region
  name     = "controlgraph-signing"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]
}

resource "google_kms_crypto_key" "signing" {
  for_each = local.signing_key_purposes

  name                          = each.value.name
  key_ring                      = google_kms_key_ring.controlgraph.id
  purpose                       = "ASYMMETRIC_SIGN"
  skip_initial_version_creation = true
  destroy_scheduled_duration    = "2592000s"
  labels                        = merge(local.common_labels, { purpose = each.key })

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_version" "initial" {
  for_each = local.signing_key_purposes

  crypto_key = google_kms_crypto_key.signing[each.key].id
  state      = "ENABLED"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "capability_signer" {
  crypto_key_id = google_kms_crypto_key.signing["capability"].id
  role          = "roles/cloudkms.signer"
  member        = google_service_account.workloads["issuer"].member
}

resource "google_kms_crypto_key_iam_member" "evidence_signer" {
  crypto_key_id = google_kms_crypto_key.signing["evidence"].id
  role          = "roles/cloudkms.signer"
  member        = google_service_account.workloads["evidence_writer"].member
}

resource "google_kms_crypto_key_iam_member" "capability_public_key_viewer" {
  for_each = toset([
    "api",
    "executor",
    "recovery",
    "verifier",
  ])

  crypto_key_id = google_kms_crypto_key.signing["capability"].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = google_service_account.workloads[each.value].member
}

resource "google_kms_crypto_key_iam_member" "evidence_public_key_viewer" {
  crypto_key_id = google_kms_crypto_key.signing["evidence"].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = google_service_account.workloads["api"].member
}

resource "google_kms_crypto_key_iam_member" "capability_version_reader" {
  for_each = local.capability_version_readers

  crypto_key_id = google_kms_crypto_key.signing["capability"].id
  role          = google_project_iam_custom_role.controlgraph["kms_version_reader"].name
  member        = google_service_account.workloads[each.value].member
}

resource "google_kms_crypto_key_iam_member" "evidence_version_reader" {
  for_each = local.evidence_version_readers

  crypto_key_id = google_kms_crypto_key.signing["evidence"].id
  role          = google_project_iam_custom_role.controlgraph["kms_version_reader"].name
  member        = google_service_account.workloads[each.value].member
}

resource "google_kms_key_ring_iam_member" "ci_key_administrator" {
  key_ring_id = google_kms_key_ring.controlgraph.id
  role        = "roles/cloudkms.admin"
  member      = google_service_account.workloads["ci_terraform"].member
}
