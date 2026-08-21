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
      boundary = "the coordinator authority facade for the named database"
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
    kms_capability_version_read = {
      api      = "cloudkms.googleapis.com"
      boundary = "state and algorithm metadata for the configured capability-signing key version"
    }
    kms_evidence_public_key_read = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured evidence-signing public key version"
    }
    kms_evidence_sign = {
      api      = "cloudkms.googleapis.com"
      boundary = "the configured evidence-signing key version"
    }
    kms_evidence_version_read = {
      api      = "cloudkms.googleapis.com"
      boundary = "state and algorithm metadata for the configured evidence-signing key version"
    }
    kms_signing_key_admin = {
      api      = "cloudkms.googleapis.com"
      boundary = "the dedicated ControlGraph signing key ring without signature-use permission"
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
      boundary = "the internal executor service with application-separated task and recovery-facade routes"
    }
    run_evidence_writer_invoke = {
      api      = "run.googleapis.com"
      boundary = "the internal evidence-writer service"
    }
    run_issuer_invoke = {
      api      = "run.googleapis.com"
      boundary = "the internal capability issuer service"
    }
    run_operation_read = {
      api      = "run.googleapis.com"
      boundary = "read-only Cloud Run operation status within the dedicated ControlGraph project"
    }
    run_recovery_invoke = {
      api      = "run.googleapis.com"
      boundary = "the fixed recovery task handler"
    }
    run_reference_invoke = {
      api      = "run.googleapis.com"
      boundary = "the disposable reference target probe"
    }
    reference_target_act_as = {
      api      = "iam.googleapis.com"
      boundary = "the fixed reference-target runtime service account"
    }
    run_target_canary_or_promote = {
      api      = "run.googleapis.com"
      boundary = "traffic on the one bound target through the executor application contract"
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
      boundary = "the fixed execution queue only"
    }
    tasks_recovery_enqueue = {
      api      = "cloudtasks.googleapis.com"
      boundary = "the fixed recovery queue"
    }
    task_caller_act_as = {
      api      = "iam.googleapis.com"
      boundary = "the two fixed Cloud Tasks OIDC caller service accounts"
    }
    task_oidc_token_mint = {
      api      = "iamcredentials.googleapis.com"
      boundary = "OIDC tokens for only the two fixed task-caller service accounts"
    }
  }

  identity_expected_allows = {
    api = toset([
      "firestore_authority_read",
      "kms_capability_public_key_read",
      "kms_capability_version_read",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
      "run_coordinator_invoke",
    ])
    coordinator = toset([
      "firestore_authority_read",
      "firestore_authority_write",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
      "run_issuer_invoke",
      "run_evidence_writer_invoke",
      "run_verifier_invoke",
      "task_caller_act_as",
      "tasks_execution_enqueue",
      "tasks_recovery_enqueue",
    ])
    issuer = toset([
      "firestore_authority_read",
      "kms_capability_sign",
      "kms_capability_version_read",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
    ])
    executor = toset([
      "firestore_authority_read",
      "kms_capability_public_key_read",
      "kms_capability_version_read",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
      "reference_target_act_as",
      "run_coordinator_invoke",
      "run_operation_read",
      "run_target_canary_or_promote",
    ])
    recovery = toset([
      "firestore_authority_read",
      "kms_capability_public_key_read",
      "kms_capability_version_read",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
      "run_executor_invoke",
    ])
    verifier = toset([
      "firestore_authority_read",
      "kms_capability_public_key_read",
      "kms_capability_version_read",
      "kms_evidence_public_key_read",
      "kms_evidence_version_read",
      "monitoring_health_read",
      "run_reference_invoke",
      "run_evidence_writer_invoke",
      "run_target_snapshot",
    ])
    evidence_writer = toset([
      "kms_evidence_public_key_read",
      "kms_evidence_sign",
      "kms_evidence_version_read",
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
      "kms_signing_key_admin",
      "storage_terraform_state",
    ])
    operator = toset([
      "run_api_invoke",
      "tasks_queue_control",
    ])
    cloud_tasks_service_agent = toset([
      "task_oidc_token_mint",
    ])
  }

  # Runtime bindings appear only when their exact resources exist. Keeping
  # implemented and pending domains distinct prevents a design-time allow from
  # being presented as an effective IAM grant.
  identity_implemented_allows = merge(
    { for identity in keys(local.identity_expected_allows) : identity => toset([]) },
    {
      api = toset([
        "firestore_authority_read",
        "kms_capability_public_key_read",
        "kms_capability_version_read",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
        "run_coordinator_invoke",
      ])
      coordinator = toset([
        "firestore_authority_read",
        "firestore_authority_write",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
        "run_issuer_invoke",
        "run_evidence_writer_invoke",
        "run_verifier_invoke",
        "task_caller_act_as",
        "tasks_execution_enqueue",
        "tasks_recovery_enqueue",
      ])
      issuer = toset([
        "firestore_authority_read",
        "kms_capability_sign",
        "kms_capability_version_read",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
      ])
      executor = toset([
        "firestore_authority_read",
        "kms_capability_public_key_read",
        "kms_capability_version_read",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
        "reference_target_act_as",
        "run_coordinator_invoke",
        "run_operation_read",
        "run_target_canary_or_promote",
      ])
      recovery = toset([
        "firestore_authority_read",
        "kms_capability_public_key_read",
        "kms_capability_version_read",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
        "run_executor_invoke",
      ])
      verifier = toset([
        "firestore_authority_read",
        "kms_capability_public_key_read",
        "kms_capability_version_read",
        "kms_evidence_public_key_read",
        "kms_evidence_version_read",
        "monitoring_health_read",
        "run_reference_invoke",
        "run_evidence_writer_invoke",
        "run_target_snapshot",
      ])
      evidence_writer = toset([
        "kms_evidence_public_key_read",
        "kms_evidence_sign",
        "kms_evidence_version_read",
      ])
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
        "kms_signing_key_admin",
        "storage_terraform_state",
      ])
      operator = toset([
        "run_api_invoke",
        "tasks_queue_control",
      ])
      cloud_tasks_service_agent = toset([
        "task_oidc_token_mint",
      ])
    },
  )

  controlgraph_identity_members = merge(
    { for role, account in google_service_account.workloads : role => account.member },
    {
      operator                  = var.operator_principal
      cloud_tasks_service_agent = "serviceAccount:service-${var.project_number}@gcp-sa-cloudtasks.iam.gserviceaccount.com"
    },
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

check "verifier_and_evidence_writer_are_separated" {
  assert {
    condition = (
      !contains(local.identity_expected_allows.verifier, "firestore_authority_write") &&
      !contains(local.identity_expected_allows.verifier, "kms_evidence_sign") &&
      contains(local.identity_expected_allows.verifier, "kms_evidence_public_key_read") &&
      contains(local.identity_expected_allows.verifier, "kms_evidence_version_read") &&
      contains(local.identity_expected_allows.verifier, "run_evidence_writer_invoke") &&
      !contains(local.identity_expected_allows.coordinator, "kms_evidence_sign") &&
      contains(local.identity_expected_allows.coordinator, "kms_evidence_public_key_read") &&
      contains(local.identity_expected_allows.coordinator, "kms_evidence_version_read") &&
      !contains(local.identity_expected_allows.issuer, "kms_evidence_sign") &&
      contains(local.identity_expected_allows.issuer, "kms_evidence_public_key_read") &&
      contains(local.identity_expected_allows.issuer, "kms_evidence_version_read") &&
      local.identity_expected_allows.evidence_writer == toset([
        "kms_evidence_public_key_read",
        "kms_evidence_sign",
        "kms_evidence_version_read",
      ]) &&
      local.identity_implemented_allows.evidence_writer == local.identity_expected_allows.evidence_writer
    )
    error_message = "Verification, authority writes, and evidence signing must remain separate."
  }
}

check "monitoring_health_read_is_implemented_for_verifier_only" {
  assert {
    condition = (
      toset([
        for identity, allows in local.identity_expected_allows : identity
        if contains(allows, "monitoring_health_read")
      ]) == toset(["verifier"]) &&
      toset([
        for identity, allows in local.identity_implemented_allows : identity
        if contains(allows, "monitoring_health_read")
      ]) == toset(["verifier"]) &&
      !contains(
        local.iam_permission_matrix.verifier.pending_allows,
        "monitoring_health_read",
      )
    )
    error_message = "Monitoring health read must be implemented for the verifier and no other identity."
  }
}

check "operator_permissions_are_bounded" {
  assert {
    condition = (
      local.identity_expected_allows.operator == toset([
        "run_api_invoke",
        "tasks_queue_control",
      ]) &&
      local.identity_implemented_allows.operator == local.identity_expected_allows.operator
    )
    error_message = "The operator may invoke the API and control only the fixed execution queue."
  }
}

check "reference_target_act_as_is_closed" {
  assert {
    condition = (
      toset([
        for identity, allows in local.identity_expected_allows : identity
        if contains(allows, "reference_target_act_as")
      ]) == toset(["executor"]) &&
      toset([
        for identity, allows in local.identity_implemented_allows : identity
        if contains(allows, "reference_target_act_as")
      ]) == toset(["executor"]) &&
      contains(local.iam_permission_matrix.recovery.expected_denials, "reference_target_act_as")
    )
    error_message = "Reference-target actAs authority must remain implemented only for the executor mutation facade."
  }
}

check "recovery_permissions_are_implemented_and_bounded" {
  assert {
    condition = (
      local.identity_implemented_allows.recovery == local.identity_expected_allows.recovery &&
      contains(local.identity_implemented_allows.recovery, "run_executor_invoke") &&
      contains(local.identity_implemented_allows.recovery, "kms_evidence_public_key_read") &&
      contains(local.identity_implemented_allows.recovery, "kms_evidence_version_read") &&
      !contains(local.identity_implemented_allows.recovery, "run_target_canary_or_promote") &&
      !contains(local.identity_implemented_allows.recovery, "reference_target_act_as") &&
      !contains(local.identity_implemented_allows.recovery, "run_operation_read") &&
      !contains(local.identity_implemented_allows.recovery, "kms_evidence_sign") &&
      !contains(local.identity_implemented_allows.recovery, "kms_capability_sign") &&
      !contains(local.identity_implemented_allows.recovery, "firestore_authority_write") &&
      !contains(local.identity_implemented_allows.recovery, "tasks_recovery_enqueue")
    )
    error_message = "Recovery may invoke only the sealed executor facade and verify evidence, with no direct target mutation, actAs, operation-read, signing, authority-write, or enqueue authority."
  }
}

check "executor_service_invocation_is_closed_to_task_and_recovery_callers" {
  assert {
    condition = (
      toset([
        for identity, allows in local.identity_expected_allows : identity
        if contains(allows, "run_executor_invoke")
      ]) == toset(["execution_task_caller", "recovery"]) &&
      toset([
        for identity, allows in local.identity_implemented_allows : identity
        if contains(allows, "run_executor_invoke")
      ]) == toset(["execution_task_caller", "recovery"])
    )
    error_message = "Only the execution task caller and recovery worker may invoke the executor service; application policy separates their exact routes."
  }
}

check "recovery_evidence_key_access_is_verification_only" {
  assert {
    condition = (
      toset([
        for identity, allows in local.identity_expected_allows : identity
        if contains(allows, "kms_evidence_sign")
      ]) == toset(["evidence_writer"]) &&
      contains(local.identity_expected_allows.recovery, "kms_evidence_public_key_read") &&
      contains(local.identity_expected_allows.recovery, "kms_evidence_version_read") &&
      !contains(local.identity_expected_allows.recovery, "kms_evidence_sign") &&
      !contains(local.iam_permission_matrix.recovery.pending_allows, "kms_evidence_public_key_read") &&
      !contains(local.iam_permission_matrix.recovery.pending_allows, "kms_evidence_version_read")
    )
    error_message = "Recovery may verify the exact evidence key but only the evidence writer may sign with it."
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
