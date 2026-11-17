# Test organization

- Frontend component-level smoke tests live with the web source and run with Vitest.
- Browser-level smoke tests live in `apps/web/e2e` and run with Playwright.
- API tests live in `apps/api/tests` and run with Pytest.

Keep tests focused on implemented behavior. Add security-boundary, privacy, and tenant-isolation coverage as those capabilities are designed and introduced.
