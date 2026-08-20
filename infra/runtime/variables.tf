variable "project_id" {
  description = "Dedicated ControlGraph project identifier."
  type        = string

  validation {
    condition     = can(regex("^controlgraph-canary-[a-z0-9]{6,10}$", var.project_id))
    error_message = "project_id must use controlgraph-canary- followed by 6 to 10 lowercase letters or digits."
  }
}

variable "region" {
  description = "Sole regional boundary for runtime resources."
  type        = string

  validation {
    condition     = var.region == "us-central1"
    error_message = "region must be exactly us-central1."
  }
}

variable "state_bucket_name" {
  description = "Retained ControlGraph-only Terraform state bucket."
  type        = string
}

variable "bootstrap_state_prefix" {
  description = "Fixed bootstrap state prefix."
  type        = string
  default     = "bootstrap"

  validation {
    condition     = var.bootstrap_state_prefix == "bootstrap"
    error_message = "bootstrap_state_prefix must be exactly bootstrap."
  }
}

variable "foundation_state_prefix" {
  description = "Fixed foundation state prefix."
  type        = string
  default     = "foundation"

  validation {
    condition     = var.foundation_state_prefix == "foundation"
    error_message = "foundation_state_prefix must be exactly foundation."
  }
}

variable "controller_image" {
  description = "Reviewed controller image in the dedicated registry, pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.controller_image))
    error_message = "controller_image must be pinned to a lowercase sha256 digest."
  }
}

variable "reference_target_stable_image" {
  description = "Stable reference-target image in the dedicated registry, pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.reference_target_stable_image))
    error_message = "reference_target_stable_image must be pinned to a lowercase sha256 digest."
  }
}

variable "reference_target_candidate_image" {
  description = "Candidate reference-target image in the dedicated registry, pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.reference_target_candidate_image))
    error_message = "reference_target_candidate_image must be pinned to a lowercase sha256 digest."
  }
}

variable "reference_target_candidate_configuration_sha256" {
  description = "Canonical ControlGraph digest of the reviewed candidate Cloud Run revision configuration."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.reference_target_candidate_configuration_sha256))
    error_message = "reference_target_candidate_configuration_sha256 must be one lowercase SHA-256 digest."
  }
}

variable "reference_target_deployment_phase" {
  description = "Explicit stable-then-candidate revision staging phase; creation establishes the safe traffic baseline."
  type        = string

  validation {
    condition     = contains(["stable", "candidate"], var.reference_target_deployment_phase)
    error_message = "reference_target_deployment_phase must be stable or candidate."
  }
}

variable "operator_principal" {
  description = "Exact human principal allowed to invoke the operator API."
  type        = string

  validation {
    condition     = can(regex("^user:[^@[:space:]]+@[^@[:space:]]+$", var.operator_principal))
    error_message = "operator_principal must be one explicit user email principal."
  }
}

variable "operator_subject" {
  description = "Exact Google identity subject allowed to invoke the operator API."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]{5,31}$", var.operator_subject))
    error_message = "operator_subject must be one explicit numeric Google identity subject."
  }
}
