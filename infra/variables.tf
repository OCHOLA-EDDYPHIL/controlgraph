variable "project_id" {
  description = "Google Cloud project that will eventually host the controller."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must resemble a valid Google Cloud project ID."
  }
}

variable "region" {
  description = "Google Cloud region for the future controller service."
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must resemble a Google Cloud region such as us-central1."
  }
}

variable "service_name" {
  description = "Name reserved for the future controller service."
  type        = string
  default     = "controlgraph-canary"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", var.service_name))
    error_message = "service_name must be a lowercase Cloud Run-compatible name."
  }
}

variable "controller_image" {
  description = "Immutable image reference for the future controller deployment."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-fA-F]{64}$", var.controller_image))
    error_message = "controller_image must be pinned to a sha256 image digest."
  }
}

variable "minimum_instances" {
  description = "Reserved minimum instance count for future module wiring."
  type        = number
  default     = 0

  validation {
    condition     = var.minimum_instances >= 0 && floor(var.minimum_instances) == var.minimum_instances
    error_message = "minimum_instances must be a non-negative integer."
  }
}

variable "maximum_instances" {
  description = "Reserved maximum instance count for future module wiring."
  type        = number
  default     = 2

  validation {
    condition     = var.maximum_instances >= 1 && floor(var.maximum_instances) == var.maximum_instances
    error_message = "maximum_instances must be a positive integer."
  }
}
