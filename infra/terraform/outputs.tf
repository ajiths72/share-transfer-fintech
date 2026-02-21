output "argocd_namespace" {
  value = var.argocd_namespace
}

output "argocd_application_names" {
  value = [for k, v in local.apps : "finshare-${k}"]
}
