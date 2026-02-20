# Terraform IaC (Argo CD + GitOps App)

This Terraform stack installs Argo CD in your Kubernetes cluster and bootstraps the `finshare` Argo CD Application.

## Prerequisites

- Terraform >= 1.6
- Kubernetes cluster access via kubeconfig
- `kubectl` access verified

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
- Argo CD continuously syncs `deploy/overlays/prod` from your repo

## Notes

- Create your runtime app secret in cluster (do not commit plaintext secrets):
  - `finshare-secrets` in namespace `finshare`
  - keys: `APP_SECRET`, `DATABASE_URL`
- Ensure your GHCR image is public or configure imagePullSecrets.
