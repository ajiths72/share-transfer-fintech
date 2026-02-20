output "argocd_namespace" {
  value = var.argocd_namespace
}

output "argocd_application_names" {
  value = [for k, v in kubernetes_manifest.finshare_argocd_apps : v.manifest.metadata.name]
}
