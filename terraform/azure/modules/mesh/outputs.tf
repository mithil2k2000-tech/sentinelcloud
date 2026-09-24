output "app_namespace" {
  value = kubernetes_namespace.app.metadata[0].name
}
