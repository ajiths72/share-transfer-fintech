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
      path         = "deploy/overlays/dev"
      namespace    = "finshare-dev"
      db_size      = "2Gi"
      db_cpu_req   = "50m"
      db_mem_req   = "128Mi"
      db_cpu_limit = "300m"
      db_mem_limit = "256Mi"
    }
    staging = {
      path         = "deploy/overlays/staging"
      namespace    = "finshare-staging"
      db_size      = "5Gi"
      db_cpu_req   = "100m"
      db_mem_req   = "256Mi"
      db_cpu_limit = "500m"
      db_mem_limit = "512Mi"
    }
    prod = {
      path         = "deploy/overlays/prod"
      namespace    = "finshare-prod"
      db_size      = "10Gi"
      db_cpu_req   = "150m"
      db_mem_req   = "256Mi"
      db_cpu_limit = "700m"
      db_mem_limit = "768Mi"
    }
  }
}

resource "random_password" "db_password" {
  for_each = local.apps
  length   = 24
  special  = false
}

resource "random_password" "app_secret" {
  for_each = local.apps
  length   = 48
  special  = true
}

resource "kubernetes_secret_v1" "postgres_auth" {
  for_each = local.apps

  metadata {
    name      = "postgres-auth"
    namespace = each.value.namespace
  }

  type = "Opaque"

  data = {
    POSTGRES_USER     = "finshare"
    POSTGRES_PASSWORD = random_password.db_password[each.key].result
    POSTGRES_DB       = "finshare"
  }
}

resource "kubernetes_persistent_volume_claim_v1" "postgres_data" {
  for_each         = local.apps
  wait_until_bound = false

  metadata {
    name      = "postgres-data"
    namespace = each.value.namespace
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "standard"
    resources {
      requests = {
        storage = each.value.db_size
      }
    }
  }
}

resource "kubernetes_service_v1" "postgres" {
  for_each = local.apps

  metadata {
    name      = "postgres"
    namespace = each.value.namespace
    labels = {
      app = "postgres"
    }
  }

  spec {
    selector = {
      app = "postgres"
    }
    port {
      name        = "postgres"
      port        = 5432
      target_port = 5432
    }
  }
}

resource "kubernetes_deployment_v1" "postgres" {
  for_each = local.apps

  metadata {
    name      = "postgres"
    namespace = each.value.namespace
    labels = {
      app = "postgres"
    }
  }

  spec {
    replicas = 1
    selector {
      match_labels = {
        app = "postgres"
      }
    }

    template {
      metadata {
        labels = {
          app = "postgres"
        }
      }
      spec {
        container {
          name              = "postgres"
          image             = "public.ecr.aws/docker/library/postgres:16-alpine"
          image_pull_policy = "IfNotPresent"
          port {
            container_port = 5432
          }
          env_from {
            secret_ref {
              name = kubernetes_secret_v1.postgres_auth[each.key].metadata[0].name
            }
          }
          resources {
            requests = {
              cpu    = each.value.db_cpu_req
              memory = each.value.db_mem_req
            }
            limits = {
              cpu    = each.value.db_cpu_limit
              memory = each.value.db_mem_limit
            }
          }
          volume_mount {
            name       = "data"
            mount_path = "/var/lib/postgresql/data"
          }
        }
        volume {
          name = "data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.postgres_data[each.key].metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_secret_v1" "finshare_secrets" {
  for_each = local.apps

  metadata {
    name      = "finshare-secrets"
    namespace = each.value.namespace
  }

  type = "Opaque"

  data = {
    APP_SECRET   = random_password.app_secret[each.key].result
    DATABASE_URL = "postgresql://finshare:${random_password.db_password[each.key].result}@postgres.${each.value.namespace}.svc.cluster.local:5432/finshare"
  }

  depends_on = [kubernetes_service_v1.postgres, kubernetes_deployment_v1.postgres]
}

resource "null_resource" "finshare_argocd_apps" {
  for_each   = local.apps
  depends_on = [time_sleep.wait_for_argocd_crds, kubernetes_secret_v1.finshare_secrets]

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
