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
