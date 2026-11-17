# Architecture overview

## Current foundation

This repository is a pnpm/uv monorepo with a web application and one modular API application:

```text
Browser
  └── apps/web (Next.js App Router, TypeScript, Tailwind CSS)

apps/api (FastAPI, Pydantic Settings)
  ├── versioned HTTP routes (/api/v1)
  ├── shared configuration and structured logging
  ├── optional SQLAlchemy engine and session layer
  └── reserved application modules
        ├── identity
        ├── tenants
        ├── detection
        ├── intelligence
        ├── investigations
        ├── billing
        ├── audit
        └── integrations

PostgreSQL (optional local development dependency)
```

The API currently exposes only liveness and readiness checks. The database URL is optional: readiness reports `not_configured` when absent, and checks the connection when present. There are no models or migrations yet. Reserved modules contain no business logic.

`packages/shared-contracts` is an intentionally empty starting point for future shared API contracts. It must not become a copy of backend business logic.

## Design direction

- Keep the initial backend as a modular monolith with clear application boundaries. Extract services only when measured scale or independent operational requirements support doing so.
- Keep HTTP contracts versioned and separate from persistence models.
- Keep persistence optional until a real domain schema and migrations are designed.
- Introduce provider-neutral adapters at actual integration boundaries, including future local/cloud inference. No AI provider is selected or integrated.
- Treat tenancy, privacy, retention, authorization, and auditability as architecture requirements before adding sensitive workflows.

## Planned, not implemented

Authentication, authorization, tenant management, detection, risk assessment, AI inference, investigations, intelligence feeds, billing, developer integrations, security audit storage, and production deployment are future capabilities. Their presence as directories or documentation headings is not implementation evidence.
