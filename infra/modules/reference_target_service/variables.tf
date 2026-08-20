variable "project_id" {
  description = "Dedicated ControlGraph project identifier."
  type        = string
}

variable "region" {
  description = "Fixed reference-target region."
  type        = string
}

variable "service_account" {
  description = "Dedicated reference-target runtime identity with no ControlGraph grants."
  type        = string
}

variable "stable_image" {
  description = "Stable marker image pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.stable_image))
    error_message = "stable_image must be pinned to a lowercase sha256 digest."
  }
}

variable "candidate_image" {
  description = "Candidate marker image pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.candidate_image))
    error_message = "candidate_image must be pinned to a lowercase sha256 digest."
  }
}

variable "deployment_phase" {
  description = "Explicit stable-then-candidate revision staging selector; creation establishes the safe traffic baseline."
  type        = string

  validation {
    condition     = contains(["stable", "candidate"], var.deployment_phase)
    error_message = "deployment_phase must be stable or candidate."
  }
}

variable "network" {
  description = "Dedicated ControlGraph VPC network resource identifier."
  type        = string
}

variable "subnetwork" {
  description = "Dedicated ControlGraph regional subnetwork resource identifier."
  type        = string
}
