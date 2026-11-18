# Test organization

- Frontend component-level smoke tests live with the web source and run with Vitest.
- Browser-level smoke tests live in `apps/web/e2e` and run with Playwright.
- API tests live in `apps/api/tests` and run with Pytest. Identity and tenancy tests use an isolated in-memory SQLite fixture with foreign-key enforcement; the Alembic migration is separately validated against local PostgreSQL.

Keep tests focused on implemented behavior. API tests mount isolated test-only FastAPI routes to exercise the reusable authentication and tenant dependencies and verify their HTTP behavior. This does not mean application product routes currently mount those dependencies or that a complete authorization policy exists. Extend security-boundary, privacy, and tenant-isolation coverage as product capabilities are introduced.
