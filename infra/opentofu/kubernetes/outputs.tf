output "namespace" {
  description = "Namespace managed by this OpenTofu example."
  value       = kubernetes_namespace.crustacian.metadata[0].name
}
