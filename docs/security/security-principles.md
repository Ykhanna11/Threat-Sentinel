# Security principles

This document defines engineering principles for future implementation. The current repository is a foundation, not a production security control set, and no security certification or product protection is claimed.

- **Minimize collection:** define the purpose and retention of each data field before accepting it.
- **Establish trust boundaries:** the HTTP bearer credential is untrusted input. Only a successful
  `JwtAccessTokenVerifier` call may produce `VerifiedAccessTokenClaims`; only local identity
  resolution of those claims may produce an `AuthenticatedPrincipal` for an active user. The
  reusable FastAPI dependency performs these steps separately and is not attached to product
  routes.
  `VerifiedUserContext` remains an internal Phase 2A identity-service/tenancy contract, not proof
  of verification. Never construct trusted claims or principals from request data.
- **Separate authorization:** a verified token and authenticated local principal do not themselves
  grant organization access or permissions. Authorization decisions use local user identity,
  active local membership, locally assigned organization role, and resource scope. Provider-supplied
  roles, permissions, and organization claims never grant local authorization. Suspended users,
  organizations, and memberships remain denied. Identity resolution alone creates no membership.
  The reusable tenant dependency checks membership against the requested organization ID and
  returns only a scoped principal/organization/membership context, with no role or permission fields.
- **Preserve identity values:** use the exact verified issuer and subject pair for external identity
  resolution; reject empty values without trimming or otherwise changing the identity key. Email is
  metadata only and never links accounts.
- **Validate access-token purpose:** `JwtAccessTokenVerifier` enforces the configured
  signing-algorithm allowlist and key-type compatibility; verifies the signature, configured
  issuer/audience, required time claims, subject, and required access-token purpose/type. It rejects
  `none`, algorithm confusion, untrusted issuers, unknown keys, and tokens intended for another
  purpose. A verified ID token is not accepted as an API access token.
- **Trust authentication configuration only out of band:** the expected issuer, audience, trusted
  HTTPS JWKS endpoint, and explicit algorithm allowlist come from deployment configuration, never
  from an incoming token or request. They must be configured together; issuer/JWKS URLs reject
  plain HTTP, user information, queries, and fragments. Clock-skew and JWKS-cache settings have
  strict bounds. Configuration alone does not authenticate anyone.
- **Constrain JWKS retrieval:** fetch only the configured HTTPS URL; resolve and reject all
  non-public, reserved, loopback, private, link-local, and multicast addresses, then connect to a
  validated IP with TLS hostname verification to prevent DNS rebinding between validation and
  connection. Do not follow redirects. Bound connect/read timeouts and response size, reject
  malformed or private-key JWKS contents, and throttle refreshes for unknown key IDs.
- **Require an access-token type:** the standalone verifier accepts only `typ: at+jwt` (the RFC
  9068 access-token type marker), not
  untyped JWTs or ID tokens. Signature verification uses only configured asymmetric algorithms
  and matching public JWK types/curves; the token cannot select a key URL or key material.
- **Keep verifier failures typed and private:** invalid credentials, unavailable trusted keys, and
  unexpected verifier failures are distinct internal error types. The FastAPI dependency maps
  missing or invalid credentials and inactive accounts to generic `401` responses, missing local
  authentication configuration and trusted JWKS failures to generic `503` responses, and lets
  unexpected failures use the safe global `500` handler. It does not expose signature,
  key-selection, issuer, audience, network, parser, or internal exception details to clients.
- **Return safe authentication failures:** the verifier classifies invalid token cases as
  `InvalidAccessToken`, trusted JWKS failures as `TrustedKeySourceUnavailable`, and unexpected
  verifier errors as `AuthenticationVerifierFailure`. Missing, malformed, unsupported, or empty
  bearer credentials receive a generic `401` with a `WWW-Authenticate: Bearer` challenge.
  Operational failures fail closed and are never reported as successful authentication.
- **Authorize server-side:** the tenancy service requires an active local user and active database membership for the requested organization; an organization ID alone grants no access. Future protected routes must invoke this boundary and test cross-tenant denial.
- **Scope the first product resource:** Website/Domain Security Scans each belong to
  exactly one personal or organization scope. Authenticated users may create personal scans, whose
  ownership comes from the authenticated principal, never a client-supplied owner ID; personal scans
  require no organization membership and are readable/listable only by their owner. Organization
  scans require an active local user, active organization, and active local membership. The approved
  role matrix allows `OWNER`, `ADMIN`, and `MEMBER` to create organization scans;
  `VIEWER` is denied creation; all four may read and list organization scans. No other actions are
  approved; see the [architecture decision](../architecture/decisions.md#initial-website-domain-security-scan-authorization-service-implemented-routes-unmounted).
  The service enforces this policy, but no current product route is mounted.
- **Constrain resource lookups:** combine the resource ID and authorized personal-owner or
  organization scope in the database query; do not globally load by UUID and rely only on a later
  application-layer check. Return the same generic `404` for missing and out-of-scope resources;
  use generic `403` when the caller can access the scope but lacks permission for the action.
  Internal audit logging may distinguish denial reasons without exposing them to clients.
- **Own transactions explicitly:** request-scoped sessions are not implicitly committed. Mutations use `unit_of_work()` so success commits, exceptions roll back, and the session closes. Do not add blanket request-level commits.
- **Keep identity provider-neutral:** internal users are linked to external identities by verified issuer and subject, not email. Only provider-asserted verified email metadata is recorded as verified. Provider organization roles/claims do not confer ThreatSentinel permissions.
- **Prevent duplicate pending invitations:** PostgreSQL enforces a partial unique index on organization and normalized intended email; application transitions must still recheck status and expiry transactionally.
- **Retain an active owner:** any future membership removal, demotion, suspension, or owner transfer must validate the projected membership state with the owner-retention invariant and perform the change atomically.
- **Avoid credential persistence:** no access token, refresh token, invitation bearer token, or secret is stored by this foundation. Never log credentials, claims payloads, or invitation secrets.
- **Protect secrets:** keep credentials out of source control and logs; use a managed secret store in deployed environments. The committed `.env.example` contains local-only values.
- **Fail safely:** avoid returning stack traces, database details, submitted payloads, or secrets in client error responses. Keep health checks free of sensitive diagnostics.
- **Keep an auditable trail:** future security-relevant changes require protected, tenant-scoped audit events with deliberate retention and access controls.
- **Use defense in depth:** require dependency updates, code review, automated checks, secure transport, least privilege, backups, and incident-response procedures before production use.
- **Test security boundaries:** add threat modeling, input abuse cases, authorization and tenant-isolation tests, and secret/log redaction checks alongside the relevant features.

## Authorization concurrency protocol and validation boundary

The current implementation uses PostgreSQL's default transaction isolation and row locks. Reader
queries use `.with_for_update(read=True, of=Model)` (`FOR SHARE`); authorization-state writers
use `.with_for_update(key_share=True, of=Model)` alone (`FOR NO KEY UPDATE`). Lock order is User
rows sorted by UUID → Organization → Invitation rows sorted by UUID → Membership rows sorted by
UUID. Each lock uses a separate single-table query. There are no automatic retries, added lock
timeouts, isolation changes, or authorization caches. Deadlocks and other transient database
errors roll back the whole UOW and must not be converted into authorization denials or not-found
responses.

Implemented readers are:

- Personal scan create/list/read: lock the authenticated User, re-resolve the exact issuer/subject
  external identity mapping, confirm identity and user IDs still match the principal, then validate
  active status and access owner-scoped scans in the same UOW.
- Organization scan create/list/read and tenant membership checks: lock User → Organization →
  Membership, including inactive membership rows, before validating status and evaluating the
  existing local role/action matrix. Scope-constrained scan queries and generic 404/403 behavior
  remain intact.
- Existing-user principal resolution: lock and refresh User `FOR SHARE`, revalidate the exact
  external identity mapping, then validate active status before issuing a principal. There is no
  separate ExternalIdentity lock and no current production unlink/relink/reassignment operation.
- Organization listing: lock User first, enumerate all associated Membership rows without
  prefiltering by status, lock all relevant Organizations in UUID order, then lock Membership rows
  in UUID order. Retain the locks through authorization checks and list materialization. A
  protocol-compliant membership writer must lock User `FOR NO KEY UPDATE` first, preventing
  membership phantoms.

Organization creation locks User `FOR SHARE` and validates active status after acquiring the lock.
It retains that lock while inserting the Organization and initial OWNER Membership in the caller's
single transaction. It does not mutate User state or upgrade the User lock; `FOR SHARE` blocks a
protocol-compliant User status writer using `FOR NO KEY UPDATE`. The service and repository do not
create a nested UOW. There is no production organization-creation route or caller; any future
application boundary must own exactly one UOW spanning validation and writes. New User and
ExternalIdentity provisioning remains atomic in the existing principal-resolution UOW.

Tenant dependencies hold locks only in their own short UOW. A returned organization context
cannot substitute for authorization in the later transaction that accesses a protected resource.
Every protected service operation must make its authorization decision and access the protected
resource in the same UOW.

Future writers for user, organization, membership, invitation, or identity-link lifecycle changes
are not implemented. Before validation or mutation, every writer that changes existing
authorization-state rows must acquire `FOR NO KEY UPDATE`, follow User → Organization → Invitation
→ Membership, and sort same-type rows by UUID. In particular, future User status writers must
acquire User `FOR NO KEY UPDATE`. Membership creation/restoration locks the Organization before
inserting/restoring a Membership. Future identity reassignment locks all affected User rows in UUID
order; readers revalidate their identity mapping after the User lock. Any lifecycle writer must
meet this contract before its capability is exposed. Do not hold locks across network calls, AI
inference, or lengthy scan execution.

PostgreSQL 17 integration tests use independent sessions/connections, deterministic events,
bounded waits, and `pg_blocking_pids()` diagnostics. They cover lock blocking and ordering,
missing-membership serialization, writer-first changes, listing consistency, principal freshness,
organization creation/status races, and rollback/lock release. SQLite tests remain useful for
application behavior but are not evidence of PostgreSQL locking behavior. Local PostgreSQL test
success does not establish CI success, production deployment, or production readiness. CI runs
the PostgreSQL marker separately; its result must be checked independently. This lock protocol
requires no migration.

Protected product routes must remain unmounted until the relevant implementation and PostgreSQL
validation have been reviewed and the required CI checks and deployment-specific conditions are
met. See the [architecture decision](../architecture/decisions.md#authorization-transaction-and-concurrency-protocol-implemented-postgresql-integration-tests).

The repository now has a standalone JWT access-token verifier, a reusable FastAPI authentication
dependency, and a reusable tenant membership dependency. The tenant dependency uses the existing
active membership check in a short unit-of-work transaction; it is not attached to product routes.
Liveness remains independent of database and authentication configuration. Readiness reports
database status and local authentication-configuration completeness, but does not initialize the
verifier or probe live provider/JWKS availability. A previously unknown external identity may
create a local user and external identity mapping after successful verification; that provisioning
does not create an organization
or membership. Inactive local users are rejected, and organization access still requires an
independently established active local membership. Provider roles and organization claims do not
grant local authorization. The claims and principal types do not perform or prove cryptographic
verification by themselves. OIDC discovery, browser login/logout, refresh sessions, session
revocation, invitation delivery, membership mutation/owner transfer, a general RBAC framework
beyond the implemented service-level scan authorization policy, audit event storage, rate limiting,
and production secrets integration remain unimplemented. Service-level authorization is
implemented for the documented scan actions, but product HTTP routes remain unmounted. These
foundations are not a production security control set.

The verifier uses the configured JWKS URL directly; it does not perform OIDC discovery. The
three-second connection/read timeouts, 64 KiB response limit, 30-second unknown-key refresh
interval, and five-second minimum refresh interval are implementation safeguards, not configurable
values. Authentication/session lifecycle, revocation, browser account-onboarding flows, and any
browser login flow are deferred. Identity-record provisioning for a successfully verified unknown
issuer/subject pair is implemented separately and does not create organization membership.
No frontend authentication flow is to be introduced before the backend verification and
authorization trust boundaries are implemented and tested.
