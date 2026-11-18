# Architecture overview

## Current foundation

This repository is a pnpm/uv monorepo with a web application and one modular API application:

```text
Browser
  └── apps/web (Next.js App Router, TypeScript, Tailwind CSS)

apps/api (FastAPI, Pydantic Settings)
  ├── versioned HTTP routes (/api/v1)
  ├── shared configuration and structured logging
  ├── SQLAlchemy session layer and Alembic migrations
  └── modular application domains
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

The API currently exposes only liveness and readiness checks. The database URL remains optional at startup: readiness reports `not_configured` when absent and checks connectivity when present. An additive initial migration now defines the identity and organization schema; there are still no product-facing identity or tenant endpoints.

## Identity and tenant boundaries

- `User` is an internal account with a stable UUID. `ExternalIdentity` maps a verified provider issuer and subject to that account; the `(issuer, subject)` pair is unique. Email is optional metadata, and a verified email is never used to merge accounts or identify a user.
- `VerifiedAccessTokenClaims` is a minimal, immutable internal contract for output from a
  successful verifier; it requires issuer, subject, audience, issuance time, and expiration, and
  excludes the bearer token and arbitrary provider claims. `AuthenticationProvider` is only a
  provider-neutral protocol and now returns this type. The type does not itself verify a token.
- Optional verifier settings are loaded out of band from the environment. The expected issuer,
  audience, trusted HTTPS JWKS URL, and explicit signing-algorithm allowlist must be configured as
  a complete set. These values are not accepted from tokens or requests, and configuring them
  alone does not activate authentication.
- `VerifiedUserContext` remains the Phase 2A internal issuer/subject and email-metadata contract
  used by identity and tenancy services; it is neither an untrusted request schema nor proof of
  token verification. `IdentityService.resolve_authenticated_principal()` resolves verified
  claims to an active local user and returns an immutable `AuthenticatedPrincipal` containing
  local and external identity IDs. That principal is not an authorization grant.
- When a successfully verified issuer/subject pair is not known locally, identity resolution may
  create a local user and external identity mapping. This does not create an organization or
  membership; access still requires a separately established active local membership.
- `JwtAccessTokenVerifier` validates compact JWTs whose protected header has `typ: at+jwt`.
  It validates signatures only with compatible keys from the configured JWKS endpoint and only
  with configured asymmetric algorithms; issuer, audience, required time claims, subject, and
  optional email metadata are validated before returning `VerifiedAccessTokenClaims`.
  `get_current_principal` is a reusable FastAPI dependency that uses the provider to verify a
  bearer credential and resolves the claims to an active local identity. The reusable tenant
  dependency returns an `ActiveOrganizationContext` only after checking active local membership.
  No application product route currently mounts either dependency; the API router currently
  mounts health routes only. Authentication configuration is optional for this health-only API.
  OIDC discovery and login flows are not implemented.
- `TrustedJwksKeyStore` rejects non-public DNS answers, pins HTTPS connections to validated IP
  addresses while retaining TLS hostname verification, does not follow redirects, uses three
  second connection/read timeouts, limits JWKS responses to 64 KiB, and caps cached keys using
  configuration. Refreshes are throttled, including requests for unknown key IDs.
- `Organization`, `OrganizationMembership`, and `OrganizationInvitation` are persisted separately from identity. A user may have memberships in multiple organizations. Organization creation explicitly gives the creating active user an owner membership; resolving an identity alone creates no membership. Owner/admin/member/viewer are the initial coarse roles; scan-specific and fine-grained/custom permission enforcement remains future work.
- `OrganizationService` requires a `VerifiedUserContext`, resolves it to a local user by issuer and subject, then checks the active organization and membership in the database. A caller-supplied organization UUID alone is not an authorization check. Provider organization roles or claims are not consumed as application permissions.
- Pending invitations have a database-enforced unique key per organization and normalized email (lowercase and trimmed); terminal invitations do not block reissue. Invitation delivery and state-transition endpoints are not implemented.
- `get_session()` is a request-scoped session resource, not a commit boundary. Mutating application operations must run inside `unit_of_work()`, which owns commit on success, rollback on exceptions, and session closure.
- `require_active_owner()` validates a projected membership state before a future role/removal operation. Membership changes, owner transfer/removal rules, invitation state-transition services, and automatic enforcement that an organization retain an active owner are not implemented; call the invariant from such operations before exposing management endpoints.

These are application and persistence foundations, not a complete authentication or authorization system. No application product route currently consumes the authentication or tenant dependencies. A verified external token produces verified claims; local identity resolution produces an authenticated principal; the tenant dependency produces a scoped active-organization context after checking local membership. Future product routes must explicitly consume the appropriate dependency.

`packages/shared-contracts` is an intentionally empty starting point for future shared API contracts. It must not become a copy of backend business logic.

## Planned authorization for the first product resource

The first resource is a Website/Domain Security Scan. Its model, scoped repository, and
authorization-aware service are implemented; production routes and a scanning engine are not. A
scan belongs to one logical scope: either a personal workspace or an organization workspace.
Personal scans are owned by the authenticated principal assigned by the server; authenticated
users may create personal scans and list/read only their own. Personal scans do not require
organization membership. Organization scans require an active local user, active organization,
and active local membership and use the local membership role policy.
The approved matrix allows `OWNER`, `ADMIN`, and `MEMBER` to create
organization scans, while `VIEWER` cannot; all four roles may read and list organization scans.
No other actions are approved. See the [authorization decision](./decisions.md#initial-website-domain-security-scan-authorization-planned)
for the complete matrix and denial/transaction rules.

The server determines ownership and scope. Data access constrains resource ID and authorized scope
together; a missing resource and an out-of-scope resource return the same generic `404`. Permission
denial for an in-scope resource returns a generic `403`. The service performs authorization and
scan access in one unit of work, but the approved row-lock protocol needed to serialize concurrent
authorization-state changes is not implemented or PostgreSQL-validated. See the
[approved transaction and concurrency protocol](./decisions.md#approved-transaction-and-concurrency-protocol-implementation-pending).

## Design direction

- Keep the initial backend as a modular monolith with clear application boundaries. Extract services only when measured scale or independent operational requirements support doing so.
- Keep HTTP contracts versioned and separate from persistence models.
- Keep the database optional for health-only startup; database-backed operations require a configured database and applied migrations.
- Keep external authentication at a provider adapter boundary, while local user state, organization membership, and authorization remain application-owned.
- Introduce provider-neutral adapters at actual integration boundaries, including future local/cloud inference. No AI provider is selected or integrated.
- Treat tenancy, privacy, retention, authorization, and auditability as architecture requirements before adding sensitive workflows.

## Planned, not implemented

Authentication and tenant dependencies are reusable foundations, but protected product routes, OIDC discovery and browser flows, invitation delivery and acceptance, fine-grained permissions, detection, risk assessment, AI inference, investigations, intelligence feeds, billing, developer integrations, security audit storage, and production deployment are future capabilities. The identity and tenancy records and service boundaries described above are implemented foundations, not completed product capabilities.
