# Security principles

This document defines engineering principles for future implementation. The current repository is a foundation, not a production security control set, and no security certification or product protection is claimed.

- **Minimize collection:** define the purpose and retention of each data field before accepting it.
- **Establish trust boundaries:** validate input at API boundaries; do not treat client-provided tenant, identity, risk, or authorization claims as trusted. External identity claims must pass through a future token-verification adapter before becoming a `VerifiedUserContext`.
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

The repository now has identity, organization, membership, invitation persistence, service-level organization access checks, an explicit unit-of-work boundary, and a reusable owner-retention invariant. It does not yet have token verification, authentication middleware, protected product routes, membership mutation/owner transfer operations, invitation transition services, fine-grained permission enforcement, audit event storage, rate limiting, or production secrets integration. These foundations are not a production security control set.
