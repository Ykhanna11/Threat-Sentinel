# Architecture decisions

These decisions are the approved foundation for the initial project scaffold. They do not imply that future product capabilities have been implemented.

| Area | Decision |
| --- | --- |
| Repository | Monorepo with `apps/web`, `apps/api`, `packages/shared-contracts`, infrastructure, docs, scripts, and tests. |
| Frontend | Next.js App Router, strict TypeScript, Tailwind CSS, shadcn/ui-compatible component organization, and Lucide icons. |
| Backend | Python with FastAPI, Pydantic Settings, SQLAlchemy 2.x, and Alembic. |
| Database | PostgreSQL, with a connection layer and migration environment but no premature business schema. |
| JavaScript packages | pnpm workspace. |
| Python packages | uv project and lockfile. |
| Testing | Vitest for frontend smoke tests, Pytest for API tests, and Playwright for browser-level testing. |
| Local infrastructure | Docker Compose for PostgreSQL only. |
| Deployment | Managed cloud direction; no production provider selected. Avoid provider lock-in where practical. |
| AI | Future multi-provider design with local and cloud inference adapters; no vendor dependency is introduced. |
| Service topology | A modular monolith until demonstrated scaling or operational requirements justify extraction. No Kubernetes or speculative microservices. |

## Consequences

- `/api/v1` is the HTTP API version boundary.
- `DATABASE_URL` is optional for the initial service. Database-backed routes must not be added without explicit readiness, failure, and migration behavior.
- Future shared TypeScript contracts should describe API boundaries, not reimplement backend rules.
- Product security and privacy decisions must precede collection or processing of user-provided threat evidence.
