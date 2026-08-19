locals {
  iam_permission_domains = {
    artifact_registry_images_write = {
      api      = "artifactregistry.googleapis.com"
      boundary = "the regional ControlGraph image repository"
    }
    firestore_authority_read = {
      api      = "firestore.googleapis.com"
      boundary = "the named ControlGraph authority database"
    }
    firestore_authority_write = {
      api      = "firestore.googleapis.com"
      boundary = "create and update records in the named ControlGraph authority database"
    }
    github_impersonate_image_builder = {
      api      = "iamcredentials.googleapis.com"
      boundary = "the CI image-builder service account through the exact image-builder environment principal"
    }
    github_impersonate_terraform = {
      api      = "iamcredentials.googleapis.com"
      boundary = "the CI Terraform service account through the exact Terraform environment principal"
    }
    github_oidc_exchange = {
      api      = "sts.googleapis.com"
      boundary = "the exact GitHub repository, owner, main ref, and deploy workflow condition"
    }
    kms_capability_public_key_read = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured capability-signing public key version"
    }
    kms_capability_sign = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured capability-signing key version"
    }
    kms_evidence_public_key_read = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured evidence-signing public key version"
    }
    kms_evidence_sign = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured evidence-signing key version"
    }
    logging_audit_read = {
      api      = "logging.googleapis.com"
      boundary = "the dedicated project audit-log view"
    }
    monitoring_health_read = {
      api      = "monitoring.googleapis.com"
      boundary = "the closed reference-target health metric set"
    }
    run_api_invoke = {
      api      = "run.googleapis.com"
      boundary = "the authenticated operator API service"
    }
    run_coordinator_invoke = {
      api      = "run.googleapis.com"
      boundary = "the internal coordinator service"
    }
    run_executor_invoke = {
      api      = "run.googleapis.com"
      boundary = "the fixed execution task handler"
    }
    run_issuer_invoke = {
      api      = "run.googleapis.com"
      boundary = "the internal capability issuer service"
    }
    run_operation_read = {
      api      = "run.googleapis.com"
      boundary = "operations produced by the bound reference target"
    }
    run_recovery_invoke = {
      api      = "run.googleapis.com"
      boundary = "the fixed recovery task handler"
    }
    run_reference_invoke = {
      api      = "run.googleapis.com"
      boundary = "the disposable reference target probe"
    }
    run_target_canary_or_promote = {
      api      = "run.googleapis.com"
      boundary = "traffic on the one bound target through the executor application contract"
    }
    run_target_restore_stable = {
      api      = "run.googleapis.com"
      boundary = "traffic on the one bound target through the restore-only recovery contract"
    }
    run_target_snapshot = {
      api      = "run.googleapis.com"
      boundary = "the one bound reference target and its immutable revisions"
    }
    run_verifier_invoke = {
      api      = "run.googleapis.com"
      boundary = "the internal verifier service"
    }
    storage_terraform_state = {
      api      = "storage.googleapis.com"
      boundary = "objects in the retained ControlGraph Terraform state bucket"
    }
    tasks_execution_enqueue = {
      api      = "cloudtasks.googleapis.com"
      boundary = "the fixed execution queue"
    }
    tasks_queue_control = {
      api      = "cloudtasks.googleapis.com"
      boundary = "one explicitly bound ControlGraph queue"
    }
    tasks_recovery_enqueue = {
      api      = "cloudtasks.googleapis.com"
      boundary = "the fixed recovery queue"
    }
  }

  identity_expected_allows = {
    api = toset([
      "run_coordinator_invoke",
    ])
    coordinator = toset([
      "firestore_authority_read",
      "firestore_authority_write",
      "run_issuer_invoke",
      "run_verifier_invoke",
      "tasks_execution_enqueue",
      "tasks_recovery_enqueue",
    ])
    issuer = toset([
      "firestore_authority_read",
      "kms_capability_sign",
    ])
    executor = toset([
      "firestore_authority_read",
      "firestore_authority_write",
      "kms_capability_public_key_read",
      "run_operation_read",
      "run_target_canary_or_promote",
      "run_target_snapshot",
    ])
    recovery = toset([
      "firestore_authority_read",
      "firestore_authority_write",
      "kms_capability_public_key_read",
      "run_operation_read",
      "run_target_restore_stable",
      "run_target_snapshot",
    ])
    verifier = toset([
      "firestore_authority_read",
      "firestore_authority_write",
      "kms_capability_public_key_read",
      "kms_evidence_sign",
      "monitoring_health_read",
      "run_reference_invoke",
    ])
    reference = toset([])
    execution_task_caller = toset([
      "run_executor_invoke",
    ])
    recovery_task_caller = toset([
      "run_recovery_invoke",
    ])
    ci_image_builder = toset([
      "artifact_registry_images_write",
      "github_impersonate_image_builder",
      "github_oidc_exchange",
    ])
    ci_terraform = toset([
      "github_impersonate_terraform",
      "github_oidc_exchange",
      "storage_terraform_state",
    ])
    operator = toset([
      "run_api_invoke",
    ])
  }

  # Runtime resource bindings are added with #26-#29, when their exact resource
  # names exist. Keeping implemented and pending domains distinct prevents this
  # matrix from presenting a design-time allow as an effective IAM grant.
  identity_implemented_allows = merge(
    { for identity in keys(local.identity_expected_allows) : identity => toset([]) },
    {
      ci_image_builder = toset([
        "artifact_registry_images_write",
        "github_impersonate_image_builder",
        "github_oidc_exchange",
      ])
      ci_terraform = toset([
        "github_impersonate_terraform",
        "github_oidc_exchange",
        "storage_terraform_state",
      ])
    },
  )

  controlgraph_identity_members = merge(
    { for role, account in google_service_account.workloads : role => account.member },
    { operator = var.operator_principal },
  )

  iam_permission_matrix = {
    for identity, principal in local.controlgraph_identity_members : identity => {
      principal          = principal
      expected_allows    = sort(tolist(local.identity_expected_allows[identity]))
      implemented_allows = sort(tolist(local.identity_implemented_allows[identity]))
      pending_allows     = sort(tolist(setsubtract(local.identity_expected_allows[identity], local.identity_implemented_allows[identity])))
      expected_denials   = sort(tolist(setsubtract(toset(keys(local.iam_permission_domains)), local.identity_expected_allows[identity])))
    }
  }

  identity_expected_api_allows = {
    for identity, allows in local.identity_expected_allows : identity => toset([
      for permission in allows : local.iam_permission_domains[permission].api
    ])
  }

  iam_api_matrix = {
    for identity, principal in local.controlgraph_identity_members : identity => {
      principal       = principal
      expected_allows = sort(tolist(local.identity_expected_api_allows[identity]))
      implemented_allows = sort(distinct([
        for permission in local.identity_implemented_allows[identity] : local.iam_permission_domains[permission].api
      ]))
      expected_denials = sort(tolist(setsubtract(local.required_services, local.identity_expected_api_allows[identity])))
    }
  }
}

check "iam_matrix_covers_every_identity" {
  assert {
    condition = (
      toset(keys(local.controlgraph_identity_members)) == toset(keys(local.identity_expected_allows))
    )
    error_message = "The IAM matrix must contain one allow row for every ControlGraph identity."
  }
}

check "iam_matrix_uses_known_domains" {
  assert {
    condition = alltrue([
      for allows in values(local.identity_expected_allows) :
      length(setsubtract(allows, toset(keys(local.iam_permission_domains)))) == 0
    ])
    error_message = "Every expected IAM allow must name a permission domain in the matrix catalog."
  }
}

check "iam_matrix_uses_required_apis" {
  assert {
    condition = alltrue([
      for domain in values(local.iam_permission_domains) :
      contains(local.required_services, domain.api)
    ])
    error_message = "Every IAM permission domain must use an API in the complete required-services set."
  }
}

check "iam_matrix_does_not_overstate_implemented_grants" {
  assert {
    condition = alltrue([
      for identity, implemented in local.identity_implemented_allows :
      length(setsubtract(implemented, local.identity_expected_allows[identity])) == 0
    ])
    error_message = "Every implemented IAM domain must be a subset of that identity's reviewed expected allows."
  }
}

output "iam_permission_matrix" {
  description = "Expected, implemented, pending, and denied domains for every ControlGraph identity and cloud API."
  value = {
    domains           = local.iam_permission_domains
    permission_matrix = local.iam_permission_matrix
    api_matrix        = local.iam_api_matrix
  }
}
