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
| 2D.7 — Account suspension, reactivation, privileged recovery | Deferred by design | No legitimate administrative/recovery actor or lifecycle control plane exists. Users cannot suspend other accounts or reactivate any inactive account. Existing inactive accounts are denied; onboarding cannot reactivate them. No durable audit-event store exists. |
| 2D.8 — Organization archival and platform recovery | Unavailable | Owner-authorized suspension/reactivation is implemented. No archival endpoint, platform administrator, organization recovery flow, or hidden bypass is introduced. |
| 2D.9 — Invitation delivery | Deferred by infrastructure | No email-delivery integration exists. Creating an invitation does not claim that email was sent; the authorized response contains the one-time token for the caller's delivery process. |
| 2D.10 — Frontend lifecycle UI | Deferred by architecture | The current web application is a static landing page without authentication state or an API client. No parallel frontend authentication architecture is introduced. |

## Lifecycle API

All routes below are under `/api/v1` and require the established authenticated-principal
dependency unless otherwise stated.

- `GET`, `PATCH /account/profile`
- `POST /account/deactivate`
- `POST`, `GET /organizations`
- `PATCH /organizations/{organization_id}`
- `POST /organizations/{organization_id}/suspend`
- `POST /organizations/{organization_id}/reactivate`
- `GET /organizations/{organization_id}/members`
- `PATCH /organizations/{organization_id}/members/{membership_id}`
- `POST /organizations/{organization_id}/ownership-transfer`
- `POST /organizations/{organization_id}/invitations`
- `DELETE /organizations/{organization_id}/invitations/{invitation_id}`
- `POST /organization-invitations/accept`

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

Phase 2D should not be called fully complete while account suspension/reactivation, legitimate
administrative recovery, durable lifecycle audit events, and organization owner-loss recovery
remain unavailable. Those transitions require an independently authenticated and authorized
control plane, including explicit policies for preserving ownership, revoking access, auditing, and
emergency access—not a self-service or unauthenticated shortcut. The full Phase 2D.2 trust and
ownership assessment is in [account-lifecycle-assessment.md](./account-lifecycle-assessment.md).
