import pytest
from sqlalchemy import Engine, inspect, text

pytestmark = pytest.mark.postgres_integration


def test_postgres_17_database_is_initialized_from_alembic_migrations(
    postgres_migrated_engine: Engine,
) -> None:
    with postgres_migrated_engine.connect() as connection:
        version = connection.scalar(text("SHOW server_version_num"))
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))

    assert version is not None
    assert int(version) // 10000 == 17
    assert revision == "c7b1e4a2d903"
    assert {
        "users",
        "external_identities",
        "organizations",
        "organization_memberships",
        "organization_invitations",
        "security_audit_events",
        "security_scans",
    }.issubset(inspect(postgres_migrated_engine).get_table_names())
