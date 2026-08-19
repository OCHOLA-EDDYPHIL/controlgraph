locals {
  ci_wif_environments = {
    ci_image_builder = "controlgraph-image-builder"
    ci_terraform     = "controlgraph-terraform"
  }

  github_wif_principal_sets = {
    for role, environment in local.ci_wif_environments :
    role => "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/attribute.environment/${environment}"
  }
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "controlgraph-github"
  display_name              = "ControlGraph GitHub"
  description               = "Keyless identity pool restricted to the reviewed main-branch workflow."

  depends_on = [google_project_service.required]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-main"
  display_name                       = "ControlGraph GitHub main"
  description                        = "GitHub OIDC provider pinned to one repository, owner, ref, and workflow."

  attribute_mapping = {
    "google.subject"                = "assertion.sub"
    "attribute.repository"          = "assertion.repository"
    "attribute.repository_id"       = "assertion.repository_id"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    "attribute.ref"                 = "assertion.ref"
    "attribute.workflow_ref"        = "assertion.workflow_ref"
    "attribute.environment"         = "assertion.environment"
  }

  attribute_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_owner_id}'",
    "assertion.ref == '${var.github_ref}'",
    "assertion.workflow_ref == '${var.github_workflow_ref}'",
    "assertion.environment in ['controlgraph-image-builder', 'controlgraph-terraform']",
  ])

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  lifecycle {
    prevent_destroy = true
  }
}

check "github_wif_ci_identities_are_separate" {
  assert {
    condition     = length(toset(values(local.ci_wif_environments))) == length(local.ci_wif_environments)
    error_message = "Each CI service account must use a distinct GitHub environment principal."
  }
}

check "github_wif_is_main_only" {
  assert {
    condition = (
      var.github_ref == "refs/heads/main" &&
      endswith(var.github_workflow_ref, "@refs/heads/main")
    )
    error_message = "GitHub workload identity federation must be pinned to main and a workflow ref ending in @refs/heads/main."
  }
}

check "github_wif_repository_is_exact" {
  assert {
    condition = (
      var.github_repository == "OCHOLA-EDDYPHIL/controlgraph" &&
      var.github_repository_id == "1338673889" &&
      var.github_owner_id == "154631735" &&
      var.github_workflow_ref == "OCHOLA-EDDYPHIL/controlgraph/.github/workflows/deploy.yml@refs/heads/main"
    )
    error_message = "GitHub workload identity federation must remain pinned to the exact ControlGraph repository, numeric owner and repository IDs, and reviewed CI workflow."
  }
}

output "github_workload_identity_provider" {
  description = "Full provider name used by reviewed GitHub workflows for keyless authentication."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "github_workload_identity_environments" {
  description = "GitHub environment names that separate image-build and Terraform impersonation."
  value       = local.ci_wif_environments
}
