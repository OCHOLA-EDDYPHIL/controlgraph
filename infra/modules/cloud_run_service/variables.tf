variable "project_id" {
  description = "Dedicated ControlGraph project identifier."
  type        = string
}

variable "region" {
  description = "Fixed Cloud Run region."
  type        = string
}

variable "service_name" {
  description = "Cloud Run service name."
  type        = string

  validation {
    condition     = can(regex("^controlgraph-[a-z0-9-]+$", var.service_name))
    error_message = "service_name must be a ControlGraph-prefixed Cloud Run name."
  }
}

variable "description" {
  description = "Identity-safe service description."
  type        = string
}

variable "custom_audiences" {
  description = "Additional exact ID-token audiences accepted by this service."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for audience in var.custom_audiences :
      length(audience) >= 1 &&
      length(audience) <= 256 &&
      audience == trimspace(audience)
    ]) && length(jsonencode(var.custom_audiences)) <= 32768
    error_message = "custom_audiences must contain bounded, non-empty exact values."
  }
}

variable "container_image" {
  description = "Controller image pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-f]{64}$", var.container_image))
    error_message = "container_image must be pinned to a lowercase sha256 digest."
  }
}

variable "service_account" {
  description = "Exact runtime service account email."
  type        = string
}

variable "ingress" {
  description = "Explicit Cloud Run ingress mode."
  type        = string

  validation {
    condition = contains([
      "INGRESS_TRAFFIC_ALL",
      "INGRESS_TRAFFIC_INTERNAL_ONLY",
      "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
    ], var.ingress)
    error_message = "ingress must be an explicit supported Cloud Run v2 mode."
  }
}

variable "environment" {
  description = "Non-secret, role-bound controller configuration."
  type        = map(string)
}

variable "labels" {
  description = "Standard ControlGraph labels."
  type        = map(string)
}

variable "network" {
  description = "Dedicated Direct VPC egress network."
  type        = string
}

variable "subnetwork" {
  description = "Dedicated Direct VPC egress subnetwork."
  type        = string
}

variable "vpc_egress" {
  description = "Explicit Direct VPC egress routing mode."
  type        = string
  default     = "PRIVATE_RANGES_ONLY"

  validation {
    condition     = contains(["PRIVATE_RANGES_ONLY", "ALL_TRAFFIC"], var.vpc_egress)
    error_message = "vpc_egress must be PRIVATE_RANGES_ONLY or ALL_TRAFFIC."
  }
}

variable "minimum_instances" {
  description = "Minimum serving instances."
  type        = number
  default     = 0
}

variable "maximum_instances" {
  description = "Maximum serving instances."
  type        = number
  default     = 2
}

variable "concurrency" {
  description = "Maximum concurrent requests per instance."
  type        = number
  default     = 8
}

variable "timeout" {
  description = "Maximum request duration."
  type        = string
  default     = "30s"
}

variable "cpu" {
  description = "Container CPU limit."
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Container memory limit."
  type        = string
  default     = "512Mi"
}
