# FinShare Transfer

Advanced fintech web application for online share transfer and market execution with live quote refresh, market/limit buys, maker-checker controls, TOTP 2FA, revocable sessions, PostgreSQL support, migrations, Docker, CI tests, and OpenAPI docs.

## Core features

- Secure auth with PBKDF2 password hashing and signed bearer tokens
- Session-backed auth tokens with explicit session revocation
- TOTP 2FA setup/enable/disable
- Trader transfer request flow
- Market buy flow for listed symbols (immediate execution)
- Limit buy flow for listed symbols (pending until market <= limit)
- Live quote refresh with automatic pending limit-order execution checks
- Compliance/Admin maker-checker approval and rejection for transfers
- Atomic settlement execution (share + cash leg)
- Role-based portfolio and order views
- Tamper-evident audit chain (hash-linked event logs)

## Default seeded users

- `alice@fintrade.com` / `alice123` (TRADER)
- `bob@fintrade.com` / `bob123` (TRADER)
- `compliance@fintrade.com` / `comply123` (COMPLIANCE)
- `admin@fintrade.com` / `admin123` (ADMIN)

## Run locally (SQLite)

```bash
cd /Applications/share-transfer-fintech
python3 backend/migrate.py
python3 backend/app.py
```

Open `http://localhost:8080`.

## Run with Docker + PostgreSQL

```bash
docker compose up --build
```

App: `http://localhost:8080`

## Environment variables

- `DATABASE_URL`
  - SQLite default: `sqlite:////Applications/share-transfer-fintech/backend/fintech.db`
  - PostgreSQL example: `postgresql://finshare:finshare@localhost:5432/finshare`
- `APP_SECRET` (required in non-dev)
- `PORT` (default `8080`)
- `TOKEN_TTL_SECONDS` (default `28800`)

## Migrations

```bash
python3 backend/migrate.py
```

Applies SQL migrations from:
- `backend/migrations/sqlite`
- `backend/migrations/postgres`

## Tests

```bash
pytest -q
```

## OpenAPI

- Spec file: `/Applications/share-transfer-fintech/docs/openapi.yaml`
- Hosted by app: `GET /docs/openapi.yaml`

## Key APIs

- `POST /api/2fa/setup`
- `POST /api/2fa/enable`
- `POST /api/2fa/disable`
- `GET /api/sessions`
- `POST /api/sessions/revoke`
- `POST /api/sessions/revoke-all`
- `POST /api/logout`
- `GET /api/market/symbols`
- `POST /api/market/buy`
- `GET /api/market/orders`
- `POST /api/market/limit-buy`
- `GET /api/market/limit-orders`
- `POST /api/market/limit-orders/{id}/cancel`

## CI/CD (GitHub Actions + Terraform + ArgoCD GitOps)

### What is included

- CI workflow: unit tests + Docker build + Trivy FS/image scans
- CD workflow: build/push image to GHCR + Trivy image scan + GitOps image tag update
- Terraform workflow: fmt/validate + optional plan/apply automation
- Terraform IaC: installs Argo CD and bootstraps FinShare Argo Applications for dev/staging/prod
- GitOps manifests: Kustomize overlays for dev/staging/prod

### Artifact repository

- Docker images are published to **GHCR**:
  - `ghcr.io/<owner>/<repo>:sha-<commit_sha>`
  - `ghcr.io/<owner>/<repo>:latest`

### Required repository secrets

- `KUBE_CONFIG_B64` (base64-encoded kubeconfig for the target cluster)

### Required one-time updates

1. Set `repoURL` in:
   - `/Applications/share-transfer-fintech/deploy/argocd/application-dev.yaml`
   - `/Applications/share-transfer-fintech/deploy/argocd/application-staging.yaml`
   - `/Applications/share-transfer-fintech/deploy/argocd/application-prod.yaml`
2. Create Kubernetes secret `finshare-secrets` in each namespace:
   - `finshare-dev`
   - `finshare-staging`
   - `finshare-prod`
3. Ensure GHCR package visibility is set as needed (public for open-source pull).

### Pipeline files

- `/Applications/share-transfer-fintech/.github/workflows/ci.yml`
- `/Applications/share-transfer-fintech/.github/workflows/cd.yml`
- `/Applications/share-transfer-fintech/.github/workflows/promote.yml`
- `/Applications/share-transfer-fintech/.github/workflows/release-tag.yml`
- `/Applications/share-transfer-fintech/.github/workflows/release-image.yml`
- `/Applications/share-transfer-fintech/.github/workflows/terraform.yml`
- `/Applications/share-transfer-fintech/infra/terraform/*`
- `/Applications/share-transfer-fintech/deploy/base/*`
- `/Applications/share-transfer-fintech/deploy/overlays/dev/*`
- `/Applications/share-transfer-fintech/deploy/overlays/staging/*`
- `/Applications/share-transfer-fintech/deploy/overlays/prod/*`
- `/Applications/share-transfer-fintech/deploy/argocd/application-*.yaml`

### Environment promotion and release strategy

- `main` push:
  - CI runs tests + Trivy scans
  - CD builds `ghcr.io/<owner>/<repo>:sha-<commit>` and auto-updates **dev** overlay
- Manual promotion (`Promote` workflow):
  - Promote any image tag to `staging` or `prod`
  - Uses GitHub Environment gates for approval (`staging`, `prod`)
- Release tags:
  - `Release Tag` workflow creates `vX.Y.Z` Git tag + GitHub release
  - `Release Image` workflow builds/pushes `ghcr.io/<owner>/<repo>:vX.Y.Z`

### Configure GitHub environments

Create environments in repo settings:

- `staging`
- `prod`
- `production` (used for release tag creation)

Set required reviewers on `prod` and `production` for approval gates.

### Promotion example

1. Create release tag `v1.2.0` using `Release Tag` workflow.
2. Promote to staging with `image_tag=v1.2.0`.
3. Validate staging.
4. Promote to prod with `image_tag=v1.2.0`.
