# Phase 2 roadmap and implementation crosswalk

This crosswalk reflects repository implementation and local validation. A feature is not considered
complete because it has a route or schema alone. No remote CI run, production deployment, or
independent security review is implied.

| Phase / milestone | Status | Implementation and evidence |
| --- | --- | --- |
| 2A — Local identity and tenancy foundations | Preserved | Users map to external identities by exact `(issuer, subject)`; email is metadata, not an account-link key. Organization and membership persistence is retained. |
| 2B — Verified authentication and authorization boundary | Preserved | Configured JWT verification resolves to an active local principal; provider roles/claims do not authorize. Protected operations fail closed. |
| 2C — Tenant-scoped scan persistence | Preserved | Scan persistence is protected by service-level scope and role checks in one UOW; existing tenant-isolation and PostgreSQL lock tests remain. |
| 2D.1 — Account onboarding | Implemented and tested | A successfully verified issuer/subject mapping is provisioned idempotently; uniqueness handles concurrent creation, while an existing inactive account remains inactive. No email-only linking is used. |
| 2D.2 — Account profile and self-deactivation | Implemented and tested | `GET`/`PATCH /api/v1/account/profile` expose only the account's `display_name` and creation time. `PATCH` rejects extra/protected fields. `POST /api/v1/account/deactivate` requires explicit confirmation, affects only the authenticated account, retains identity/membership history, and rejects loss of the last active OWNER. |
| 2D.3 — Organization lifecycle | Implemented and tested | Authenticated users can create and list organizations; creation and initial active OWNER membership share one transaction. Owner/admin detail updates are tenant-scoped. Owners can suspend/reactivate an organization; suspension revokes pending invitations and reactivation does not revive them. |
| 2D.4 — Membership lifecycle and ownership | Implemented and tested | Authorized members can list memberships. Owner/admin role and status changes are restricted by the existing role policy; invitations add/restore eligible memberships. Only an owner can transfer ownership to another active member. An active owner is retained across protected changes. |
| 2D.5 — Invitation lifecycle | Implemented and tested | The active caller, organization, membership, and invitation-role permission are checked before recipient eligibility is queried. Owners/admins create invitations within role limits; owners alone may invite admins. Tokens are random, single-use, expire after seven days, and only SHA-256 hashes are persisted. Acceptance requires the exact verified identity bound at invitation creation. Only authorized inviters can learn whether an address is eligible; invitations still require an existing active user with a verified identity. Tokens are returned once in the authorized create response. |
| 2D.6 — PostgreSQL constraints and concurrency | Implemented and locally validated | Alembic adds profile/invitation constraints and invalidates legacy pending invitations that lack secure token/identity binding. PostgreSQL 17 tests exercise ownership, membership, invitation, identity-onboarding races, rollback, and the canonical User → Organization → Invitation → Membership lock order. Migration downgrade/re-upgrade and `alembic check` passed locally. |
| 2D.7 — Account suspension, reactivation, privileged recovery | Deferred by design | No legitimate administrative/recovery actor or lifecycle control plane exists. Users cannot suspend other accounts or reactivate any inactive account. Existing inactive accounts are denied; onboarding cannot reactivate them. Privileged recovery authority and owner-loss recovery remain unavailable despite the separate audit-event implementation. |
| 2D.8 — Organization archival and platform recovery | Partially implemented and deferred | Owner-only archive/restore is implemented. Archive is allowed only from active; restore only from archived. Suspended organizations cannot be archived or restored, archived organizations deny mutations and audit access, and owner-loss/platform recovery remain unavailable. |
| 2D.9 — Invitation delivery | Deferred by infrastructure | No email-delivery integration exists. Creating an invitation does not claim that email was sent; the authorized response contains the one-time token for the caller's delivery process. |
| 2D.10 — Frontend lifecycle UI | Deferred by architecture | The current web application is a static landing page without authentication state or an API client. No parallel frontend authentication architecture is introduced. |
| 2D.11 — Organization archive and restoration | Implemented and tested | Owner-only archive and restore endpoints exist. Archiving revokes pending invitations; restoring returns an archived organization to active status. |
| 2D.12 — Durable tenant audit events | Implemented and locally tested | Organization creation and successful supported lifecycle mutations append audit records atomically. Selected organization, membership, invitation, and tenant-authorization denials plus account-export failures are recorded in a separate failure UOW after rollback. Denial events are associated with a tenant only when the verified actor still has an active membership in its active organization; cross-tenant denials remain unassociated. Successful audit-log reads are recorded after results are materialized, so the read event is not returned by that same read. Request IDs correlate events and HTTP requests; actors come from verified principals. Owners/admins can read active-organization events; suspended and archived organizations deny audit access. Database storage is durable, not tamper-proof. |
| 2D.13 — Account data export | Implemented and tested | `GET /account/export` returns self-scoped account and membership data. It excludes identity metadata, credentials, bearer tokens, refresh tokens, and invitation secrets. Authorization comes only from the resolved active authenticated principal. |
| 2D.14 — Sensitive endpoint abuse protection | Partially implemented | A configurable in-process per-client/per-path limit covers sensitive mutations, exports, and audit-event reads; audit reads share a client bucket across organization IDs. Storage is bounded and expires. It is local and best-effort; separate API workers do not share state. Distributed enforcement requires a separately designed atomic shared store. |

## Lifecycle API

All routes below are under `/api/v1` and require the established authenticated-principal
dependency unless otherwise stated.

- `GET`, `PATCH /account/profile`
- `POST /account/deactivate`
- `POST`, `GET /organizations`
- `PATCH /organizations/{organization_id}`
- `POST /organizations/{organization_id}/suspend`
- `POST /organizations/{organization_id}/reactivate`
- `POST /organizations/{organization_id}/archive`
- `POST /organizations/{organization_id}/restore`
- `GET /organizations/{organization_id}/audit-events`
- `GET /organizations/{organization_id}/members`
- `PATCH /organizations/{organization_id}/members/{membership_id}`
- `POST /organizations/{organization_id}/ownership-transfer`
- `POST /organizations/{organization_id}/invitations`
- `DELETE /organizations/{organization_id}/invitations/{invitation_id}`
- `POST /organization-invitations/accept`
- `GET /account/export`

Services own policy and persistence repositories own database access; routes wrap mutations and
authorization-sensitive reads in a unit of work. Request and response schemas are separate from
SQLAlchemy models. Tenant scope and role are checked on the server for every management operation.

## Ownership and lock contract

Authorization-state writers lock User rows in sorted UUID order, then Organization, Invitation
rows in sorted UUID order when needed, and Membership rows in sorted UUID order. Writers use
`FOR NO KEY UPDATE`; authorization readers use `FOR SHARE`. Organization creation commits the
organization and its initial owner membership atomically. Membership role/status changes and
ownership transfers validate the projected membership state before flushing. Only an explicit,
atomic owner transfer may replace the active owner role. Organization suspension holds the
organization lifecycle lock and revokes pending invitations in the same transaction. No locks are
held across network calls.

Self-deactivation also follows User → Organization → Membership ordering. It locks the active
caller's User row, locks all organizations where the caller has an active OWNER membership in UUID
order, then locks the related memberships in UUID order. Each organization must retain another
active OWNER whose User is active. The operation retains all memberships and roles and does not
revoke an external identity-provider session or already issued JWT.

Invitation creation first uses a short authorization UOW that locks and validates the caller User,
Organization, and Membership in that order. Only after the role check does it query recipient
eligibility; that query does not lock the recipient User. The UOW releases its locks before the
creation UOW, which follows the full User → Organization → Invitation → Membership order and
revalidates the caller, recipient identity, account status, organization, and role before writing.
An authorization change between the two UOWs therefore fails closed. Unauthorized callers do not
reach recipient lookup; an authorized inviter can distinguish an eligible recipient from an
unregistered, unverified, or inactive recipient. Invitations to users without an existing verified
identity remain unsupported.

## Validation and remaining work

The SQLite suite covers request/schema behavior but is not evidence of PostgreSQL locking. Run the
dedicated `postgres_integration` marker against the disposable PostgreSQL 17 test database for
concurrency guarantees. Local test results for the current checkout are recorded in the
implementation report; CI must be checked independently.

Phase 2D remains blocked for account suspension/reactivation, legitimate administrative recovery,
and organization owner-loss recovery. Those transitions require an independently authenticated
and authorized control plane, including explicit policies for preserving ownership, revoking
access, auditing, and emergency access—not a self-service or unauthenticated shortcut. Durable
audit records cover organization creation, successful supported lifecycle mutations, selected
authorization denials, account-export failures, and audit-log reads. Successful mutations and
their audit events share a transaction; denial records use a separate transaction only after the
failed operation has rolled back. Audit-write failures do not produce success-shaped responses.
The full
Phase 2D.2 trust and ownership assessment is in
[account-lifecycle-assessment.md](./account-lifecycle-assessment.md).

## Final implementation status

| Status | Phase 2 scope |
| --- | --- |
| Fully implemented and locally tested | Identity provisioning, protected JWT access, account profile/export/self-deactivation, organizations, memberships, ownership transfer, invitations, archive/restore, audit events, and PostgreSQL locking |
| Implemented but awaiting external validation | Authentication against a real OIDC provider/JWKS, distributed rate limiting, production secrets, backups, deployment, and remote CI |
| Blocked by missing trust authority | Account suspension/reactivation, privileged recovery, administrative owner-loss recovery, and organization recovery authority |
| Intentionally deferred | Invitation email delivery, browser login/OIDC discovery UI, and account permanent deletion |
| Partially implemented | In-process sensitive endpoint rate limiting; production deployments need a shared Redis-compatible or equivalent free self-hosted control |

The in-process limiter is not a distributed production control and must not be represented as such.
Durable audit records are database records, distinct from application logs. They do not make the
system tamper-proof or immutable: database administrator, backup, and retention controls remain
separately required. No audit
record stores passwords, bearer tokens, invitation tokens, or raw credential claims.

Audit retention and deletion periods are operational decisions, not implemented application
features. Database administrators control retention, archival, backup, deletion, and independent
verification; no tamper-evident log or retention-enforcement mechanism is claimed.

In concurrent organization archive/restore operations, the organization row lock determines the
winner. The first compatible transition can commit; the other revalidates state under the lock
and either finds a compatible transition or fails closed. The final state is always a valid
active or archived state with the active-owner invariant preserved.

In concurrent account export/deactivation operations, export locks the active principal User,
materializes the export, and records its audit event in the export transaction; deactivation locks
the same User and can either commit before or after that export. If export obtains the lock first,
it may return a pre-deactivation export. If deactivation obtains it first, export revalidation
returns the generic inactive-account denial. The export never combines state from two accounts or
tenants and is not an atomic snapshot across future membership changes.
