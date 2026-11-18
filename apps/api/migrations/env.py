from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from threat_sentinel_api.core.config import get_settings
from threat_sentinel_api.db.model_registry import metadata as target_metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    database_url = get_settings().database_url
    if database_url is None:
        raise RuntimeError("DATABASE_URL must be configured to run database migrations.")
    config.set_main_option("sqlalchemy.url", database_url.get_secret_value().replace("%", "%%"))

    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_on_connection(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    test_connection = config.attributes.get("connection")
    if test_connection is not None:
        run_migrations_on_connection(test_connection)
        return

    database_url = get_settings().database_url
    if database_url is None:
        raise RuntimeError("DATABASE_URL must be configured to run database migrations.")
    config.set_main_option("sqlalchemy.url", database_url.get_secret_value().replace("%", "%%"))

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        run_migrations_on_connection(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
