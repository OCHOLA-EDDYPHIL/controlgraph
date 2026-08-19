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

variable "operator_principal" {
  description = "Exact human principal allowed to invoke the operator API."
  type        = string

  validation {
    condition     = can(regex("^user:[^@[:space:]]+@[^@[:space:]]+$", var.operator_principal))
    error_message = "operator_principal must be one explicit user email principal."
  }
}
