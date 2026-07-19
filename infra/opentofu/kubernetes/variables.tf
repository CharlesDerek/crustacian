variable "namespace" {
  description = "Kubernetes namespace used for Crustacian validation resources."
  type        = string
  default     = "crustacian"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "The namespace must be a valid Kubernetes DNS label."
  }
}

variable "kubeconfig_path" {
  description = "Path to a kubeconfig file. Validation does not contact a cluster."
  type        = string
  default     = "/dev/null"
}
