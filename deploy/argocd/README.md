# ArgoCD Applications

This folder contains one Argo CD Application per environment:

- `application-dev.yaml` -> `deploy/overlays/dev`
- `application-staging.yaml` -> `deploy/overlays/staging`
- `application-prod.yaml` -> `deploy/overlays/prod`

If you use Terraform in `infra/terraform`, these Application resources are created automatically.
