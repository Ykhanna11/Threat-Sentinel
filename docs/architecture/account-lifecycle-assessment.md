# Phase 2D.2 account lifecycle assessment

This assessment reflects the implementation at baseline `68ad6dea11d6ebbd3061ff3bf5c28577a2dc4923`.
It is a scoped architecture decision, not a production-readiness or independent security-review
claim.

## Current account state and authentication boundary

`User.status` is constrained to `active`, `suspended`, or `deactivated`; new accounts default to
`active`. No application service currently transitions that status. Identity resolution provisions
unknown verified `(issuer, subject)` identities as active users, but never changes the status of an
existing user. Principal resolution checks the persisted status under a User `FOR SHARE` lock and
rejects every non-active user as a generic `401`. Protected operations revalidate active status
inside their own transaction. Email is mutable identity metadata, not an account key.

`suspended` and `deactivated` are distinct stored values, but neither has a defined application
transition or recovery workflow. They must not be exposed as arbitrary profile-editable values.
Organization and membership statuses are separate tenant lifecycle states and do not replace the
account status.

## Trusted authority

| Operation | Existing authority | Decision |
| --- | --- | --- |
| Deactivate own account | The authenticated principal resolved from a verified provider token and its exact local identity mapping | Support an explicit self-only transition from `active` to `deactivated`; do not permit status selection or another-user target input. |
| Suspend an account | None. Organization OWNER/ADMIN permissions apply only to specified tenant operations. | Defer. |
| Deactivate another account | None. An organization role is not platform account authority. | Defer. |
| Reactivate an account | None. Existing external authentication proves identity, not permission to override a local inactive state. | Defer. |
| Recover an owner who lost identity-provider access | None. No provider administrative integration, alternate control plane, or durable recovery actor exists. | Defer. |
| Restore access to an organization without an available active owner | None. Organization roles cannot confer a new recovery authority. | Defer. |

The JWT/OIDC boundary is provider-neutral and trusts issuer, subject, audience, JWKS endpoint, and
algorithm configuration supplied out of band. It consumes no provider administrator roles or
group claims. No separately authenticated platform control plane or trusted identity-provider
administrative integration exists. Email matching, an authenticated ordinary user, a client-supplied
role, or an organization identifier cannot supply those missing permissions.

There is no feasible privileged recovery option in the current architecture:

- The identity-provider integration verifies end-user access tokens only. It has no administrator
  credential, delegated management scope, or provider-specific admin authorization contract.
  Treating a token claim or email match as platform authority would create an untrusted grant; a
  future provider-admin integration would require its own narrowly scoped authentication,
  authorization, revocation, and durable audit design.
- No separately authenticated platform control plane or control-plane principal exists. Creating
  one without an established trust root, least-privilege policy, emergency revocation, and durable
  audit would manufacture administrator authority rather than recover an account safely.
- Organization OWNER/ADMIN privileges are local and tenant-scoped. Reusing them to restore an
  unavailable OWNER or another user's account would cross the existing authorization boundary and
  would not independently prove control of the affected account or organization.

Therefore privileged account recovery and organization owner restoration cannot safely be
implemented in this phase. They require a separate architecture decision and review before any
control-plane API is added.

Self-deactivation is not account recovery. It uses the already authenticated identity to authorize
only the same account, requires an explicit confirmation, and does not permit a later login to
reactivate the account. The transition preserves the User, ExternalIdentity, memberships, roles,
and historical records.

## Organization ownership and access

The existing active-owner invariant is enforced by owner retention and explicit owner transfer.
Its account-lifecycle interpretation must also require an active local user behind an active OWNER
membership when determining whether an organization retains an authorized owner.

- If the caller is the only active OWNER for any organization, self-deactivation is rejected.
- A suspended or deactivated sole OWNER cannot authenticate, and the organization has no available
  authorized owner. No current authority can repair that state. Account reactivation and
  organization recovery are not available.
- Reactivation of an account is not implemented; existing memberships are not a recovery grant.
- Permanent loss of an owner's external identity leaves no application recovery route. This is a
  documented operational limitation, not permission for support staff or a database-side bypass.
- With multiple active owners, one owner may deactivate their own account only if another active
  OWNER remains for every organization. Membership history and assigned roles are preserved;
  the deactivated user still cannot access protected APIs.

Owner checks must cover all organizations where the user has an active OWNER membership, including
suspended organizations, because an organization may later be reactivated. They must serialize
with membership and account-state writers under the canonical order:

1. User rows in UUID order.
2. Organization rows in UUID order.
3. Invitation rows in UUID order when needed.
4. Membership rows in UUID order.

The deactivation operation locks the caller's User `FOR NO KEY UPDATE`, then its owner
Organizations and their Membership rows in the established order. Under those locks it rechecks
that each organization has another active OWNER membership belonging to an active User before
changing the caller's status. No role is transferred, membership is deleted, or organization
ownership is inferred. Runtime locks require no schema change.

## Recovery, session, and audit limits

There is no durable audit-event store. Structured request/error logs do not establish an audit
trail, and this work must not claim auditability. Account deactivation does not revoke a provider
session. The application stores no refresh-session or token-revocation state, but it resolves the
local account status on protected requests; after a committed deactivation, subsequent protected
API authentication is denied even when an otherwise-valid access token is presented. A request
already authorized before the status change is not retroactively cancelled.

Suspension, account reactivation, privileged recovery, administrative owner restoration, and
durable security audit events require a separately designed trust/control plane and explicit
revocation, audit, and emergency-access policies. No such plane is created in this phase.

## Design decision

Implement only explicit, authenticated self-deactivation with a strict confirmation schema,
transactional identity/account revalidation, active-owner retention checks, and generic safe
conflict handling. Keep `suspended` unavailable as an account transition. Do not expose a status
PATCH, another-user lifecycle route, reactivation route, or recovery API. Preserve all records and
memberships. No migration is needed because the state column and check constraint already support
`deactivated`.

The change must use the existing User → Organization → Membership lock order and include
PostgreSQL integration coverage for concurrent owner deactivations and owner-retention behavior.
No durable audit mechanism exists; that blocker and the absence of reactivation/organization
recovery must remain explicit in the roadmap and security/privacy documentation.
