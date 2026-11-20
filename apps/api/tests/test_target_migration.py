from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, Table, Uuid, create_engine, inspect

API_ROOT = Path(__file__).resolve().parents[1]
PRE_TARGET_REVISION = "c7b1e4a2d903"
TARGET_REVISION = "1c2f78b9d640"


def test_target_migration_upgrades_and_downgrades_on_sqlite() -> None:
    engine = create_engine("sqlite+pysqlite://")
    try:
        with engine.connect() as connection:
            metadata = MetaData()
            Table("users", metadata, Column("id", Uuid(), primary_key=True))
            Table("organizations", metadata, Column("id", Uuid(), primary_key=True))
            metadata.create_all(connection)

            config = Config(str(API_ROOT / "alembic.ini"))
            config.attributes["connection"] = connection
            command.stamp(config, PRE_TARGET_REVISION)
            assert "security_targets" not in inspect(connection).get_table_names()

            command.upgrade(config, TARGET_REVISION)
            tables = set(inspect(connection).get_table_names())
            assert "security_targets" in tables
            assert "target_verification_challenges" in tables

            command.downgrade(config, PRE_TARGET_REVISION)
            tables = set(inspect(connection).get_table_names())
            assert "security_targets" not in tables
            assert "target_verification_challenges" not in tables
    finally:
        engine.dispose()
