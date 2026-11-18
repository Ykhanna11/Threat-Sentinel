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
| Tenant authorization | Authorization uses local user identity, active local membership, locally assigned organization role, and resource scope. Current reader paths serialize against authorization-state writers with PostgreSQL row locks. Provider-supplied roles, permissions, or organization claims never grant local access. No role hierarchy, implicit permission inheritance, or authorization caching is introduced. |
| Transaction ownership | Request-scoped `get_session()` does not commit implicitly. Scan and principal-resolution application operations use one `unit_of_work()`. Organization service/repository methods remain transaction-neutral; their caller must own one UOW spanning active-user validation, locks, and writes. |
| Invitations | A partial unique index permits only one pending invitation per organization and normalized email; terminal invitations may be reissued. Invitations can reference only a membership in the same organization. No delivery or bearer-token mechanism is implemented. |
| Owner retention | Projected membership changes must retain an active owner. A reusable domain invariant exists, but no membership mutation or ownership-transfer operations are implemented. |

## Consequences

- `/api/v1` is the HTTP API version boundary.
- `DATABASE_URL` is optional for health-only startup; database-backed operations require explicit readiness, failure, and migration behavior.
- Authentication configuration is optional for the current health-only API. Readiness reports whether the local authentication settings are configured; it does not check JWKS or provider availability.
- Future shared TypeScript contracts should describe API boundaries, not reimplement backend rules.
- External identity resolution uses the exact `(issuer, subject)` pair. A previously unknown verified identity may create a local user and external identity mapping, but this provisioning creates no organization or membership. Organization creation explicitly grants the creator the initial owner membership.
- Authentication verification, local identity resolution, and tenant authorization are separate reusable dependencies/contracts. No application product route currently mounts them.
- The first product resource is a Website/Domain Security Scan. Its model, scoped repository, and lock-protected authorization-aware service exist; production routes and a scanning engine are not implemented.
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
- Repository/service writes must be grouped in exactly one application-boundary-owned `unit_of_work()`; request session cleanup does not imply a commit. Scan and principal-resolution operations currently own one UOW each. Organization creation has no production route, so any future caller must provide this boundary.
- Persistence models are internal and must not be exposed directly as public API response contracts.
- Product security and privacy decisions must precede collection or processing of user-provided threat evidence.

### Initial Website/Domain Security Scan authorization (service implemented; routes unmounted)

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
audit logging may distinguish denial reasons without disclosing them to clients. The six service
operations enforce this policy inside one unit of work. Personal operations lock
and revalidate the local user and exact external identity mapping. Organization operations lock
and validate the user, organization, and membership in canonical order. A shared transaction
alone does not prevent authorization-state races. No role hierarchy, implicit permission
inheritance, or authorization caching is used. Product routes remain unmounted pending review,
required CI validation, and deployment-specific security work.

Domain services classify denials without returning HTTP status codes. `ScanNotFound` and
`OrganizationScopeUnavailable` represent missing or inaccessible resources/scopes and map to a
generic `404` in the API layer. `OrganizationPermissionDenied` represents an active member's
disallowed action and maps to a generic `403`. `InvalidPrincipalError` (including inactive-user
and identity-mapping revalidation failures) maps to a generic `401` with the bearer challenge.
These responses use the standard generic HTTP error envelope and do not disclose resource,
organization, membership, or internal denial details. The specific exceptions preserve their
outcome distinction; the compatibility `OrganizationAccessDenied` base is not itself mapped.
Product scan routes remain unmounted until Phase 2C.4.7.

### Authorization transaction and concurrency protocol (implemented; PostgreSQL integration tests)

The implementation uses PostgreSQL's default transaction isolation. PostgreSQL 17 is the local
and CI concurrency-test target; passing local integration tests is not evidence of production
deployment, provider equivalence, or production readiness.

All authorization-sensitive operations acquire row locks in this order:

1. User rows, sorted by UUID.
2. The organization row, when applicable.
3. Invitation rows, sorted by UUID, when applicable.
4. Membership rows, sorted by UUID.

Reader queries use SQLAlchemy `.with_for_update(read=True, of=Model)` and PostgreSQL `FOR SHARE`.
Writer queries use `.with_for_update(key_share=True, of=Model)` alone and PostgreSQL
`FOR NO KEY UPDATE`. Locks are held through the authorization decision and protected database
work, until commit or rollback. Lock primitives are separate single-table queries; authorization
does not rely on joined eager-loading to establish lock order. Locks for multiple rows of one type
are acquired one at a time in UUID order.

Current protected readers are:

- `ScanService.create_personal_scan`, `list_personal_scans`, and `get_personal_scan`: lock the
  authenticated local User `FOR SHARE`, revalidate the exact issuer/subject identity ID and user
  ID, then check active status and perform the existing owner/scope-constrained scan query in the
  same UOW.
- `ScanService.create_organization_scan`, `list_organization_scans`, and `get_organization_scan`,
  plus tenant membership authorization: lock User, Organization, then Membership `FOR SHARE`.
  The membership query includes inactive rows; status and locally stored role are checked after
  locks. Missing membership still locks the Organization, the serialization point when no
  Membership row exists. The existing permission matrix and generic 404/403 behavior are retained.
- Active-user principal resolution in `IdentityService.resolve_verified_user` and
  `resolve_authenticated_principal`: lock User `FOR SHARE`, refresh its row, then revalidate the
  exact external identity mapping before active status validation/principal issuance. No separate
  ExternalIdentity lock is used.
- Organization listing: lock User first; enumerate all of that user's memberships without an
  active-status filter; lock every relevant Organization in UUID order; then lock every relevant
  Membership in UUID order. Retain all locks through active-status filtering and list
  materialization. Membership writers acquire the user's `FOR NO KEY UPDATE` lock first, which
  prevents additions or changes from appearing as phantom memberships during listing.

Organization creation obtains the exact identity mapping, locks User `FOR SHARE`, then validates
active status after acquiring that lock. The lock remains held through insertion of the Organization
and initial active OWNER Membership in the caller's single transaction. It does not upgrade the
User lock or mutate the User row; User `FOR SHARE` blocks a protocol-compliant User status writer
using `FOR NO KEY UPDATE`. The Organization insert precedes the Membership insert. There is no
production organization-creation route or caller. The service and repository do not open nested
UOWs; a future application boundary must wrap both validation and writes in exactly one UOW.

Identity provisioning for a previously unknown verified identity continues to insert User and
ExternalIdentity atomically in the principal-resolution UOW. There is no production operation
that reassigns, unlinks, or relinks an existing identity. Any future reassignment must lock every
affected User `FOR NO KEY UPDATE` in UUID order before changing the mapping; readers must continue
to revalidate the mapping after obtaining the relevant User lock.

Tenant dependencies retain their existing short, dependency-owned UOWs. Their locks protect only
the dependency's authorization decision and end when that UOW closes. A dependency-produced
organization context is not authorization for later handler work; each protected service
operation must authorize and access its resource within its own single UOW.

Future user/organization lifecycle changes, membership creation/restoration/removal/suspension,
role changes, invitation transitions, ownership transfer, and identity relinking are not
implemented. Future writers that mutate existing authorization state must acquire `FOR NO KEY
UPDATE` before validation or mutation, follow User → Organization → Invitation → Membership, sort
same-type rows by UUID, and lock the Organization before creating/restoring a Membership. In
particular, future User status writers must acquire User `FOR NO KEY UPDATE`; organization creation
only reads User state and uses `FOR SHARE`. Any future lifecycle writer must comply before its
capability is exposed. Do not add a separate identity lock without a demonstrated requirement.

Do not add retries, arbitrary lock timeouts, isolation changes, or authorization caching. A
deadlock or other transient database failure must roll back the complete transaction, propagate
as a database failure, and must not be mapped to an authorization denial or not-found response.
Do not hold locks during network calls, AI inference, or long-running scan execution. These are
runtime row locks; no schema migration is required. SQLite tests remain useful for behavior but
do not establish lock correctness. PostgreSQL integration tests use independent connections,
events, bounded waits, and `pg_blocking_pids()` diagnostics to verify lock blocking, ordering,
writer-first observations, listing consistency, principal freshness, organization creation, and
rollback/lock release. The repository CI workflow runs the PostgreSQL marker separately; only
actual CI results validate that workflow. Product routes must remain unmounted until the relevant
implementation, local and CI PostgreSQL validation, review, and deployment-specific conditions
are met.
