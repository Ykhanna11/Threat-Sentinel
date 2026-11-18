# Test organization

- Frontend component-level smoke tests live with the web source and run with Vitest.
- Browser-level smoke tests live in `apps/web/e2e` and run with Playwright.
- API tests live in `apps/api/tests` and run with Pytest. Identity and tenancy tests use an isolated in-memory SQLite fixture with foreign-key enforcement; the Alembic migration is separately validated against local PostgreSQL.

Keep tests focused on implemented behavior. Protected scan API tests run through the mounted
versioned application, its authentication dependency, scan service, and registered exception
handlers. Isolated FastAPI applications remain useful for testing individual exception handlers
without exposing product routes. PostgreSQL integration tests use the dedicated disposable
PostgreSQL 17 test database; SQLite tests validate application behavior but do not prove row-lock
correctness.
