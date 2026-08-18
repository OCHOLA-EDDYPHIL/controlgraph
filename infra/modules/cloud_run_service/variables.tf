variable "project_id" {
  description = "Google Cloud project identifier."
  type        = string
}

variable "region" {
  description = "Google Cloud region."
  type        = string
}

variable "service_name" {
  description = "Future Cloud Run service name."
  type        = string
}

variable "container_image" {
  description = "Future controller image pinned by digest."
  type        = string

  validation {
    condition     = can(regex("^.+@sha256:[0-9a-fA-F]{64}$", var.container_image))
    error_message = "container_image must be pinned to a sha256 digest."
  }
}

variable "minimum_instances" {
  description = "Future minimum instance count."
  type        = number
}

variable "maximum_instances" {
  description = "Future maximum instance count."
  type        = number
}
