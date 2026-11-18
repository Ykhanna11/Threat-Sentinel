# Architecture decisions

These decisions are the approved foundation for the initial project scaffold. They do not imply that future product capabilities have been implemented.

| Area | Decision |
| --- | --- |
| Repository | Monorepo with `apps/web`, `apps/api`, `packages/shared-contracts`, infrastructure, docs, scripts, and tests. |
| Frontend | Next.js App Router, strict TypeScript, Tailwind CSS, shadcn/ui-compatible component organization, and Lucide icons. |
| Backend | Python with FastAPI, Pydantic Settings, SQLAlchemy 2.x, and Alembic. |
| Database | PostgreSQL is the architectural database direction. PostgreSQL 17 is the local and CI target for concurrency integration tests; no production provider has been selected. |
| JavaScript packages | pnpm workspace. |
| Python packages | uv project and lockfile. |
| Testing | Vitest for frontend smoke tests, Pytest for API tests, and Playwright for browser-level testing. |
| Local infrastructure | Docker Compose for PostgreSQL only. |
| Deployment | Managed cloud direction; no production provider selected. Avoid provider lock-in where practical. |
| AI | Future multi-provider design with local and cloud inference adapters; no vendor dependency is introduced. |
| Service topology | A modular monolith until demonstrated scaling or operational requirements justify extraction. No Kubernetes or speculative microservices. |
| Identity key | Internal users have stable UUIDs; external accounts map by the exact verified `(issuer, subject)` pair. Email is mutable metadata, not an account key or linking mechanism. |
| Authentication boundary | Keep untrusted bearer credentials, verifier-produced access-token claims, resolved local application identity, and authorization decisions separate. The provider-neutral adapter returns only the minimal typed verified claims; local identity resolution produces a principal only for an active user. Issuer, audience, JWKS URL, and allowed algorithms are trusted out-of-band settings and must be configured together. JWT verification and reusable FastAPI authentication and tenant dependencies are implemented, but no application product route currently consumes them. |
| Tenant authorization | Authorization uses local user identity, active local membership, locally assigned organization role, and resource scope. Provider-supplied roles, permissions, or organization claims never grant local access. Suspended users, organizations, and memberships are denied. No role hierarchy, implicit permission inheritance, or authorization caching is introduced initially. |
| Transaction ownership | Request-scoped `get_session()` does not commit implicitly. Mutating application operations own a transaction and cleanup through `unit_of_work()`. |
| Invitations | A partial unique index permits only one pending invitation per organization and normalized email; terminal invitations may be reissued. Invitations can reference only a membership in the same organization. No delivery or bearer-token mechanism is implemented. |
| Owner retention | Projected membership changes must retain an active owner. A reusable domain invariant exists, but no membership mutation or ownership-transfer operations are implemented. |

## Consequences

- `/api/v1` is the HTTP API version boundary.
- `DATABASE_URL` is optional for health-only startup; database-backed operations require explicit readiness, failure, and migration behavior.
- Authentication configuration is optional for the current health-only API. Readiness reports whether the local authentication settings are configured; it does not check JWKS or provider availability.
- Future shared TypeScript contracts should describe API boundaries, not reimplement backend rules.
- External identity resolution uses the exact `(issuer, subject)` pair. A previously unknown verified identity may create a local user and external identity mapping, but this provisioning creates no organization or membership. Organization creation explicitly grants the creator the initial owner membership.
- Authentication verification, local identity resolution, and tenant authorization are separate reusable dependencies/contracts. No application product route currently mounts them.
- The first product resource is a Website/Domain Security Scan. Its model, scoped repository, and authorization-aware service exist; production routes and a scanning engine are not implemented.
- `VerifiedUserContext` remains the Phase 2A issuer/subject and email-metadata contract used by
  existing identity and tenancy services; it is not a bearer credential or proof of token
  verification. The reusable authentication dependency produces `AuthenticatedPrincipal` only
  after successful token verification and active local identity resolution.
- `VerifiedAccessTokenClaims` is an internal minimal verifier-output contract: exact issuer and
  subject, audience, timezone-aware issuance and expiration, optional not-before, key ID, email
  metadata, and token type. It contains no raw token or arbitrary provider claims; extra
  role/permission claims are rejected. The type itself does not verify a token.
- Authentication verifier settings are optional for the current health-only API, but issuer,
  audience, HTTPS JWKS URL, and explicit supported algorithms must be supplied together. Missing
  configuration causes a generic 503 when the authentication dependency is invoked. The settings
  validate trusted inputs; they do not enable authentication or make a token trustworthy.
- The verifier accepts only compact JWT access tokens with the RFC 9068 `at+jwt` type
  marker, using keys from the configured JWKS URL and the configured algorithm allowlist. It pins
  HTTPS requests to resolved public IP addresses, rejects redirects, bounds response size and
  timeouts, and limits key refreshes. A reusable authentication dependency invokes the verifier,
  and a reusable tenant dependency checks local active membership; no application product route
  currently mounts them. PyJWT (MIT) and its
  `cryptography` dependency (Apache-2.0/BSD-3-Clause) are free/open-source and add no provider or
  paid service.
- Repository/service writes must be grouped in `unit_of_work()`; request session cleanup does not imply a commit.
- Persistence models are internal and must not be exposed directly as public API response contracts.
- Product security and privacy decisions must precede collection or processing of user-provided threat evidence.

### Initial Website/Domain Security Scan authorization (planned)

Each scan belongs to exactly one logical access scope: a personal workspace or an organization
workspace. The creator/audit identity is distinct from the authorization scope. The server assigns
the owner of a personal scan from the authenticated principal; client-supplied owner IDs never
establish ownership. Authenticated users may create personal scans and may list/read only their own;
personal scans do not require organization membership.

Organization scans require an active local user, active organization, and active local membership.
Only the following initial actions are approved; role names do not imply any additional permissions:

| Action | OWNER | ADMIN | MEMBER | VIEWER |
| --- | --- | --- | --- | --- |
| Create organization scan | Allow | Allow | Allow | Deny |
| Read organization scan | Allow | Allow | Allow | Allow |
| List organization scans | Allow | Allow | Allow | Allow |

Resource lookups must constrain resource ID and authorized scope together in the data-access
query. A missing resource and an out-of-scope resource return the same generic `404`; a caller
with access to the scope but without permission for the action receives a generic `403`. Internal
audit logging may distinguish denial reasons without disclosing them to clients. Sensitive
authorization checks and resource operations require the approved transaction and concurrency
protocol below; a shared transaction alone does not prevent membership-revocation races. No role
hierarchy, implicit permission inheritance, or authorization caching is used initially.

### Approved transaction and concurrency protocol (implementation pending)

This is an approved design, not an implemented or PostgreSQL-validated guarantee. PostgreSQL 17 is
the target for local and CI concurrency integration tests; the production database provider and
its runtime settings remain unselected. Do not change transaction isolation as part of this
protocol.

All authorization-sensitive operations acquire row locks in this order:

1. User rows, sorted by UUID.
2. The organization row, when applicable.
3. Invitation rows, sorted by UUID, when applicable.
4. Membership rows, sorted by UUID.

Scan-side authorization reads use PostgreSQL `FOR SHARE`. Authorization-state writers use
`FOR NO KEY UPDATE`, acquired before reading or validating the state to be changed. Hold locks
until the transaction commits or rolls back. Do not acquire these record types in a different
order.

The organization row is the serialization point for organization membership operations. This is
required because an absent membership row cannot be locked. Membership creation, restoration,
removal, suspension, role changes, and active-owner retention checks must use the same
organization-first protocol when implemented.

All six existing `ScanService` operations must eventually acquire their applicable user,
organization, and membership locks within their existing single unit of work. Preserve the
approved role/action policy, local user and membership status checks, locally stored roles,
scope-constrained scan queries, generic not-found behavior, and existing database constraints.
The existing organization-creation operation must eventually make active-user validation and
organization/initial-owner creation participate in the same transaction and locking protocol.

Future user suspension/deactivation, organization suspension/archive, membership changes,
invitation transitions, ownership transfer, and identity unlink/relink must adopt this protocol
before their workflows are exposed. These lifecycle workflows are not created by this decision.

Do not introduce automatic retries initially or choose arbitrary lock-timeout values. A deadlock
or lock-timeout failure must roll back the entire transaction and must not be reported as an
authorization denial. Do not hold authorization locks during network requests or lengthy scan
execution. Row-lock behavior is runtime transaction behavior; no migration is required for this
protocol. Do not expose organization scan operations through production routes until the locks
are implemented and validated against PostgreSQL.
