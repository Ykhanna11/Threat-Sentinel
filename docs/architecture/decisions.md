# Architecture decisions

These decisions are the approved foundation for the initial project scaffold. They do not imply that future product capabilities have been implemented.

| Area | Decision |
| --- | --- |
| Repository | Monorepo with `apps/web`, `apps/api`, `packages/shared-contracts`, infrastructure, docs, scripts, and tests. |
| Frontend | Next.js App Router, strict TypeScript, Tailwind CSS, shadcn/ui-compatible component organization, and Lucide icons. |
| Backend | Python with FastAPI, Pydantic Settings, SQLAlchemy 2.x, and Alembic. |
| Database | PostgreSQL with SQLAlchemy 2.x and Alembic; the initial schema is limited to identity and organization tenancy foundations. |
| JavaScript packages | pnpm workspace. |
| Python packages | uv project and lockfile. |
| Testing | Vitest for frontend smoke tests, Pytest for API tests, and Playwright for browser-level testing. |
| Local infrastructure | Docker Compose for PostgreSQL only. |
| Deployment | Managed cloud direction; no production provider selected. Avoid provider lock-in where practical. |
| AI | Future multi-provider design with local and cloud inference adapters; no vendor dependency is introduced. |
| Service topology | A modular monolith until demonstrated scaling or operational requirements justify extraction. No Kubernetes or speculative microservices. |
| Identity key | Internal users have stable UUIDs; external accounts map by the exact verified `(issuer, subject)` pair. Email is mutable metadata, not an account key or linking mechanism. |
| Authentication boundary | Keep untrusted bearer credentials, verifier-produced access-token claims, resolved local application identity, and authorization decisions separate. The provider-neutral adapter returns only the minimal typed verified claims; local identity resolution produces a principal only for an active user. Issuer, audience, JWKS URL, and allowed algorithms are trusted out-of-band settings and must be configured together. Their presence does not activate authentication; cryptographic verification is deferred to Task 2B.3. |
| Tenant authorization | Organizations and memberships are application-owned database records. Access requires an active local user, organization, and membership; identity-provider organization roles/claims do not grant application permissions. |
| Transaction ownership | Request-scoped `get_session()` does not commit implicitly. Mutating application operations own a transaction and cleanup through `unit_of_work()`. |
| Invitations | A partial unique index permits only one pending invitation per organization and normalized email; terminal invitations may be reissued. Invitations can reference only a membership in the same organization. No delivery or bearer-token mechanism is implemented. |
| Owner retention | Projected membership changes must retain an active owner. A reusable domain invariant exists, but no membership mutation or ownership-transfer operations are implemented. |

## Consequences

- `/api/v1` is the HTTP API version boundary.
- `DATABASE_URL` is optional for health-only startup; database-backed operations require explicit readiness, failure, and migration behavior.
- Future shared TypeScript contracts should describe API boundaries, not reimplement backend rules.
- Resolving an external identity creates no organization membership. Organization creation explicitly grants the creator the initial owner membership.
- `VerifiedUserContext` remains the Phase 2A issuer/subject and email-metadata contract used by
  existing identity and tenancy services; it is not a bearer credential or proof of token
  verification. A future authentication dependency must produce `AuthenticatedPrincipal` only
  after successful token verification and active local identity resolution.
- `VerifiedAccessTokenClaims` is an internal minimal verifier-output contract: exact issuer and
  subject, audience, timezone-aware issuance and expiration, optional not-before, key ID, email
  metadata, and token type. It contains no raw token or arbitrary provider claims; extra
  role/permission claims are rejected. The type itself does not verify a token.
- Authentication verifier settings are optional until verification is implemented, but issuer,
  audience, HTTPS JWKS URL, and explicit supported algorithms must be supplied together. The
  settings validate trusted inputs; they do not enable authentication or make a token trustworthy.
- Repository/service writes must be grouped in `unit_of_work()`; request session cleanup does not imply a commit.
- Persistence models are internal and must not be exposed directly as public API response contracts.
- Product security and privacy decisions must precede collection or processing of user-provided threat evidence.
