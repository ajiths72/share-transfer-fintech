# Terraform IaC (Argo CD + GitOps App)

This Terraform stack installs Argo CD in your Kubernetes cluster, provisions PostgreSQL + app secrets per environment, and bootstraps three Argo CD Applications:
- `finshare-dev`
- `finshare-staging`
- `finshare-prod`

## Prerequisites

- Terraform >= 1.5
- Kubernetes cluster access via kubeconfig
- `kubectl` access verified
 - `kubectl` binary available on PATH (used to apply Argo CD Application CRs after CRDs are installed)

## Usage

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars
terraform init
terraform plan
terraform apply
```

After apply:
- Argo CD is installed in `argocd` namespace
- PostgreSQL is provisioned in each app namespace (`Deployment + Service + PVC + Secret`):
  - `postgres.finshare-dev.svc.cluster.local`
  - `postgres.finshare-staging.svc.cluster.local`
  - `postgres.finshare-prod.svc.cluster.local`
- `finshare-secrets` is created in each app namespace with:
  - `APP_SECRET`
  - `DATABASE_URL`
- Argo CD continuously syncs:
  - `deploy/overlays/dev`
  - `deploy/overlays/staging`
  - `deploy/overlays/prod`

## Notes

- Ensure your GHCR image is public or configure imagePullSecrets.
- Terraform state includes generated database/app secrets; use a secure remote backend for production.
