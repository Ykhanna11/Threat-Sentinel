# Test organization

- Frontend component-level smoke tests live with the web source and run with Vitest.
- Browser-level smoke tests live in `apps/web/e2e` and run with Playwright.
- API tests live in `apps/api/tests` and run with Pytest. Identity and tenancy tests use an isolated in-memory SQLite fixture with foreign-key enforcement; the Alembic migration is separately validated against local PostgreSQL.

Keep tests focused on implemented behavior. The current tenant tests cover verified-identity-to-membership service access, not protected HTTP routes or a complete authorization policy. Extend security-boundary, privacy, and tenant-isolation coverage as those capabilities are introduced.
