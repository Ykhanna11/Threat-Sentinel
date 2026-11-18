# ThreatSentinel

ThreatSentinel is a privacy-first cybersecurity intelligence platform in development by Meta Infinium. This repository contains its engineering foundation; it is **not production-ready** and does not yet implement threat analysis, authentication flows/provider integration, billing, or other product capabilities.

## Repository

- `apps/web` — Next.js App Router application
- `apps/api` — FastAPI application, identity and tenancy domain foundations, SQLAlchemy, and Alembic
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

Liveness is independent of database and authentication configuration. Readiness reports the database status and `authentication_configuration` (`configured` or `not_configured`). When `DATABASE_URL` is set, readiness checks the database connection and returns `503` if it is unavailable. Authentication configuration status reflects only whether the required local settings are complete; readiness does not initialize the JWT verifier or JWKS infrastructure and does not verify provider reachability, token validity, or whether protected product routes exist. The current API has no database-dependent or authentication-protected product routes.

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

The example `.env` configures the API to connect to this local database. The initial migration creates the identity and organization-tenancy schema:

```bash
uv run --directory apps/api --project . alembic upgrade head
```

Identity and tenancy are not exposed through product API routes yet.

## PostgreSQL integration tests

The ordinary API suite uses in-memory SQLite. PostgreSQL integration tests are separately marked
and require an explicitly configured disposable PostgreSQL 17 database; they never fall back to
`DATABASE_URL` or `.env`.

Start the isolated local test service. It uses a test-only database and credentials, binds only
to loopback port `55432`, and stores its data in temporary memory rather than the development
database volume:

```bash
docker compose -p threatsentinel-postgres-test \
  -f infrastructure/docker/compose.postgres-test.yaml up -d --wait
export THREAT_SENTINEL_TEST_DATABASE_URL='postgresql+psycopg://threatsentinel_test:local-test-only@localhost:55432/threatsentinel_test'
```

Run the PostgreSQL integration marker. Its session-scoped fixture applies the existing Alembic
migrations to the configured test database before executing marked tests:

```bash
uv run --directory apps/api --project . pytest -m postgres_integration
```

Stop and remove only the isolated test Compose project and its resources:

```bash
docker compose -p threatsentinel-postgres-test \
  -f infrastructure/docker/compose.postgres-test.yaml down --volumes --remove-orphans
unset THREAT_SENTINEL_TEST_DATABASE_URL
```

Do not use the development Compose project, its persistent volume, or the normal `DATABASE_URL`
for these tests. The test URL is accepted only for the designated test database, user, local test
port, or the CI test service hostname. CI provides its own ephemeral PostgreSQL 17 service and
runs the marked tests separately from the SQLite suite.

## Checks and tests

```bash
pnpm lint
pnpm typecheck
pnpm test:web
pnpm test:api
uv run --directory apps/api --project . ruff check
uv run --directory apps/api --project . ruff format --check
uv run --directory apps/api --project . mypy
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

`pnpm validate` checks that required foundation files and directories exist. CI runs validation, frontend linting/type checking and Vitest, plus backend linting, formatting, type checking, and Pytest. Playwright is available for local end-to-end testing.

## Architecture and status

See [the architecture overview](docs/architecture/overview.md), [architecture decisions](docs/architecture/decisions.md), [security principles](docs/security/security-principles.md), and [privacy and data handling](docs/privacy/data-handling.md). Planned product capabilities are explicitly not represented as implemented features.
