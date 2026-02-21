resource "kubernetes_namespace" "argocd" {
  metadata {
    name = var.argocd_namespace
  }
}

resource "helm_release" "argocd" {
  name             = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  namespace        = kubernetes_namespace.argocd.metadata[0].name
  create_namespace = false
  version          = "7.7.15"

  values = [
    yamlencode({
      configs = {
        params = {
          "server.insecure" = true
        }
      }
      server = {
        service = {
          type = "LoadBalancer"
        }
      }
    })
  ]
}

resource "time_sleep" "wait_for_argocd_crds" {
  depends_on      = [helm_release.argocd]
  create_duration = "45s"
}

locals {
  kubeconfig_abs = pathexpand(var.kubeconfig_path)

  apps = {
    dev = {
      path      = "deploy/overlays/dev"
      namespace = "finshare-dev"
    }
    staging = {
      path      = "deploy/overlays/staging"
      namespace = "finshare-staging"
    }
    prod = {
      path      = "deploy/overlays/prod"
      namespace = "finshare-prod"
    }
  }
}

resource "null_resource" "finshare_argocd_apps" {
  for_each   = local.apps
  depends_on = [time_sleep.wait_for_argocd_crds]

  triggers = {
    app_name   = "finshare-${each.key}"
    repo_url   = var.gitops_repo_url
    revision   = var.gitops_revision
    path       = each.value.path
    namespace  = each.value.namespace
    argocd_ns  = var.argocd_namespace
    kubeconfig = local.kubeconfig_abs
  }

  provisioner "local-exec" {
    command = <<-EOT
      for i in $(seq 1 30); do
        if kubectl --kubeconfig="${local.kubeconfig_abs}" api-resources --api-group=argoproj.io | grep -q '^applications'; then
          break
        fi
        echo "Waiting for Argo CD Application CRD to register... ($i/30)"
        sleep 5
      done

      cat <<'YAML' | kubectl --kubeconfig="${local.kubeconfig_abs}" apply -f -
      apiVersion: argoproj.io/v1alpha1
      kind: Application
      metadata:
        name: finshare-${each.key}
        namespace: ${var.argocd_namespace}
      spec:
        project: default
        source:
          repoURL: ${var.gitops_repo_url}
          targetRevision: ${var.gitops_revision}
          path: ${each.value.path}
        destination:
          server: https://kubernetes.default.svc
          namespace: ${each.value.namespace}
        syncPolicy:
          automated:
            prune: true
            selfHeal: true
          syncOptions:
            - CreateNamespace=true
      YAML
    EOT
  }
}
