output "argocd_namespace" {
  value = var.argocd_namespace
}

output "argocd_application_name" {
  value = kubernetes_manifest.finshare_argocd_app.manifest.metadata.name
}
