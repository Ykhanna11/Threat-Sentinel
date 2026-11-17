# ThreatSentinel

ThreatSentinel is a privacy-first cybersecurity intelligence platform in development by Meta Infinium. This repository contains its initial engineering foundation; it is **not production-ready** and does not yet implement threat analysis, authentication, billing, or other product capabilities.

## Repository

- `apps/web` — Next.js App Router application
- `apps/api` — FastAPI application, database connectivity, and Alembic configuration
- `packages/shared-contracts` — reserved workspace package for future API contracts and shared TypeScript types
- `infrastructure/docker` — local PostgreSQL Compose configuration
- `infrastructure/deployment` — deployment direction and future work
- `docs` — architecture, security, and privacy foundations
- `scripts` — repository validation utilities
- `tests` — cross-project test guidance

## Requirements

- Node.js `>=22.12` and pnpm `12.16.1`
- Python `>=3.12` and [uv](https://docs.astral.sh/uv/)
- Docker Engine with Docker Compose

## Setup

From the repository root:

```bash
cp .env.example .env
pnpm install
uv sync --project apps/api --all-groups
```

`.env` contains local-only development settings. Do not put production credentials in this file or commit it.

## Run the applications

Start the web application in one terminal:

```bash
pnpm dev:web
```

Open <http://localhost:3000>.

Start the API in another terminal:

```bash
pnpm dev:api
```

The API is available at <http://127.0.0.1:8000>; interactive API documentation is at <http://127.0.0.1:8000/docs>. Liveness and readiness endpoints are `GET /api/v1/health` and `GET /api/v1/ready`.

The API starts without a database URL. Readiness reports the database as `not_configured`; when `DATABASE_URL` is set, readiness checks the connection and returns `503` if it is unavailable. The current API has no database-dependent product routes.

## Local PostgreSQL

Start PostgreSQL with persistent local storage:

```bash
pnpm db:up
```

Stop the service while retaining its data:

```bash
pnpm db:down
```

To remove the local database and its persisted data, run `pnpm db:down:volumes`. This is destructive and intended only for local development.

The example `.env` configures the API to connect to this local database. No migrations are defined yet; the Alembic environment is configured for future migrations.

## Checks and tests

```bash
pnpm lint
pnpm typecheck
pnpm test:web
pnpm test:api
```

The end-to-end browser smoke test uses Playwright. Install its Chromium browser once, then run it:

```bash
pnpm --filter @threat-sentinel/web exec playwright install chromium
pnpm test:e2e
```

On Linux hosts missing browser libraries, install Playwright's system dependencies first:

```bash
pnpm --filter @threat-sentinel/web exec playwright install-deps chromium
```

`pnpm validate` checks that required foundation files and directories exist. CI runs validation, frontend linting/type checking and Vitest, plus the backend Pytest suite. Playwright is available for local end-to-end testing.

## Architecture and status

See [the architecture overview](docs/architecture/overview.md), [architecture decisions](docs/architecture/decisions.md), [security principles](docs/security/security-principles.md), and [privacy and data handling](docs/privacy/data-handling.md). Planned product capabilities are explicitly not represented as implemented features.
