# Security principles

This document defines engineering principles for future implementation. The current repository is a foundation, not a production security control set, and no security certification or product protection is claimed.

- **Minimize collection:** define the purpose and retention of each data field before accepting it.
- **Establish trust boundaries:** the HTTP bearer credential is untrusted input. Only a future
  successful cryptographic verifier may produce `VerifiedAccessTokenClaims`; only local identity
  resolution of those claims may produce an `AuthenticatedPrincipal` for an active user.
  `VerifiedUserContext` remains an internal Phase 2A identity-service/tenancy contract, not proof
  of verification. Never construct trusted claims or principals from request data.
- **Separate authorization:** a verified token and authenticated local principal do not themselves
  grant organization access or permissions. Resolve active local user, organization, and membership
  from the database, then apply locally defined permissions. Ignore provider roles and organization
  claims for authorization; identity resolution alone creates no membership.
- **Preserve identity values:** use the exact verified issuer and subject pair for external identity
  resolution; reject empty values without trimming or otherwise changing the identity key. Email is
  metadata only and never links accounts.
- **Validate access-token purpose:** a future verifier must enforce an explicit signing-algorithm
  allowlist and key-type compatibility; verify the signature and configured issuer, audience, time
  claims, subject, and required access-token purpose/type. Reject `none`, algorithm confusion,
  untrusted issuers, unknown keys, and tokens intended for another purpose. A verified ID token
  must not be accepted as an API access token.
- **Return safe authentication failures:** distinguish missing/malformed credentials, invalid
  signature or algorithm, untrusted issuer, audience or time failures, missing subject, unknown
  key, inactive local user, and authorization denial internally. Invalid or unusable credentials
  must receive a generic `401` response without token-validation detail; authenticated users
  lacking local organization permissions receive `403`. Operational verifier/JWKS failures must
  fail closed and must not be reported as successful authentication.
- **Authorize server-side:** the tenancy service requires an active local user and active database membership for the requested organization; an organization ID alone grants no access. Future protected routes must invoke this boundary and test cross-tenant denial.
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

The repository now has a typed internal access-token-claims contract and a local
authenticated-principal resolution contract in addition to its identity, organization, membership,
invitation persistence, service-level organization access checks, explicit unit-of-work boundary,
and reusable owner-retention invariant. The claims and principal types do not perform or prove
cryptographic verification by themselves. There is still no token verifier, authentication
middleware/dependency, authentication route, protected product route, membership mutation/owner
transfer operation, invitation transition service, fine-grained permission enforcement, audit event
storage, rate limiting, or production secrets integration. These foundations are not a production
security control set.

The later verifier design must choose issuer/audience configuration, allowed algorithms and key
sources, token-type rules, clock-skew policy, and JWKS outage behavior. Authentication/session
lifecycle, revocation, onboarding of unknown identities, and any browser flow are also deferred.
No frontend authentication flow is to be introduced before the backend verification and
authorization trust boundaries are implemented and tested.
