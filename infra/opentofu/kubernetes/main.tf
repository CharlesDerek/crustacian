terraform {
  required_version = ">= 1.6.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.36"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

locals {
  app_labels = {
    "app.kubernetes.io/name"       = "crustacian"
    "app.kubernetes.io/managed-by" = "opentofu"
  }
}

resource "kubernetes_namespace" "crustacian" {
  metadata {
    name   = var.namespace
    labels = local.app_labels
  }
}

resource "kubernetes_config_map" "scan_defaults" {
  metadata {
    name      = "crustacian-scan-defaults"
    namespace = kubernetes_namespace.crustacian.metadata[0].name
    labels    = local.app_labels
  }

  data = {
    scan_mode       = "report"
    signature_fresh = "required"
  }
}
