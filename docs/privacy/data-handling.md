# Privacy and data handling

ThreatSentinel is intended to be privacy-first. The following are design requirements, not claims about implemented product behavior.

- Collect and retain only data required for an explicit feature and purpose.
- Document data categories, processing locations, retention, deletion, and access before introducing user-provided URLs, messages, or investigation evidence.
- Prefer local processing where it can satisfy the use case. Any future cloud inference or intelligence lookup must be explicit, minimized, and evaluated for provider retention and training terms.
- Do not place sensitive content, full URLs, credentials, or message bodies in routine logs, telemetry, tests, or error responses.
- Define deletion and export behavior across primary storage, derived artifacts, queues, backups, analytics, and third-party processors before launch.
- Document consent, lawful basis, subprocessors, residency, and customer controls as product and jurisdictional requirements become known.
- Keep development data synthetic and credentials local-only. Do not copy production data into development or test environments.

The identity layer stores an internal user UUID and provider issuer/subject mapping. An optional
display name is user-editable; optional provider email metadata and its verification timestamp
remain attached to the external identity. Email is never an account-link key. Organization
invitations retain the intended email, identity reference, inviter, role, and lifecycle timestamps;
these fields are personal data and require a deliberate retention/deletion policy before production
use. Invitation tokens are returned once to the authorized creator; only a SHA-256 token hash is
stored. No email delivery service is integrated.

Authenticated account-profile, organization, membership, and invitation API routes exist, but there
is no account deletion/export flow, user-suspension control plane, invitation email delivery,
analysis endpoint, cloud inference integration, analytics pipeline, or production data store.
Suspended organizations retain their memberships and historical records; pending invitations are
revoked and are not restored on reactivation. Retention and deletion controls remain a pre-production
requirement.
