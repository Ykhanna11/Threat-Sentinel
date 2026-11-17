from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = (
    "apps/web/src/app/layout.tsx",
    "apps/web/src/app/page.tsx",
    "apps/api/src/threat_sentinel_api/main.py",
    "apps/api/migrations/env.py",
    "packages/shared-contracts/package.json",
    "infrastructure/docker/compose.yaml",
    "infrastructure/deployment",
    "docs/architecture/overview.md",
    "docs/architecture/decisions.md",
    "docs/security/security-principles.md",
    "docs/privacy/data-handling.md",
    "docs/product",
    "scripts",
    "tests",
    ".github/workflows/ci.yml",
    ".env.example",
)


def main() -> int:
    missing = [path for path in REQUIRED_PATHS if not (ROOT / path).exists()]
    if missing:
        print("Project validation failed; missing required paths:")
        for path in missing:
            print(f"- {path}")
        return 1

    print(f"Project validation passed ({len(REQUIRED_PATHS)} required paths checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
