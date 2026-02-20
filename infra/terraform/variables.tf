variable "kubeconfig_path" {
  description = "Path to kubeconfig for target cluster"
  type        = string
  default     = "~/.kube/config"
}

variable "argocd_namespace" {
  description = "Namespace to install Argo CD"
  type        = string
  default     = "argocd"
}

variable "app_namespace" {
  description = "Namespace for finshare app"
  type        = string
  default     = "finshare"
}

variable "gitops_repo_url" {
  description = "Git repository URL Argo CD will track"
  type        = string
}

variable "gitops_revision" {
  description = "Git revision/branch for Argo CD"
  type        = string
  default     = "main"
}

variable "gitops_path" {
  description = "Path in repo for Kustomize overlay"
  type        = string
  default     = "deploy/overlays/prod"
}
