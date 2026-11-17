# Privacy and data handling

ThreatSentinel is intended to be privacy-first. The following are design requirements, not claims about implemented product behavior.

- Collect and retain only data required for an explicit feature and purpose.
- Document data categories, processing locations, retention, deletion, and access before introducing user-provided URLs, messages, or investigation evidence.
- Prefer local processing where it can satisfy the use case. Any future cloud inference or intelligence lookup must be explicit, minimized, and evaluated for provider retention and training terms.
- Do not place sensitive content, full URLs, credentials, or message bodies in routine logs, telemetry, tests, or error responses.
- Define deletion and export behavior across primary storage, derived artifacts, queues, backups, analytics, and third-party processors before launch.
- Document consent, lawful basis, subprocessors, residency, and customer controls as product and jurisdictional requirements become known.
- Keep development data synthetic and credentials local-only. Do not copy production data into development or test environments.

The current application has no user data model, analysis endpoint, cloud inference integration, analytics pipeline, or production data store.
