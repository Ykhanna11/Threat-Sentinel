from contextlib import nullcontext
from unittest.mock import Mock

import pytest

import conftest
from postgres_test_support import TEST_DATABASE_NAME, TEST_DATABASE_USER

TEST_DATABASE_URL = (
    "postgresql+psycopg://threatsentinel_test:fixture-secret@localhost:55432/threatsentinel_test"
)


def test_postgres_session_closes_when_consumer_raises() -> None:
    test_session = Mock()
    session_factory = Mock(return_value=test_session)
    fixture_function = conftest.postgres_session._fixture_function
    session_generator = fixture_function(session_factory)

    assert next(session_generator) is test_session
    with pytest.raises(RuntimeError, match="consumer failed"):
        session_generator.throw(RuntimeError("consumer failed"))

    test_session.close.assert_called_once_with()


def test_postgres_identity_query_error_redacts_connection_details() -> None:
    engine = Mock()
    connection = Mock()
    engine.connect.return_value = nullcontext(connection)
    original_message = f"query failed for {TEST_DATABASE_URL}"
    connection.execute.side_effect = RuntimeError(original_message)
    fixture_function = conftest.postgres_migrated_engine._fixture_function

    with pytest.raises(RuntimeError) as error:
        fixture_function(engine)

    assert original_message not in str(error.value)
    assert TEST_DATABASE_URL not in str(error.value)
    assert "fixture-secret" not in str(error.value)
    assert error.value.__suppress_context__


def test_postgres_migration_error_redacts_connection_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = Mock()
    connection = Mock()
    engine.connect.side_effect = [nullcontext(connection), nullcontext(connection)]
    connection.execute.return_value.one.return_value = (
        TEST_DATABASE_NAME,
        TEST_DATABASE_USER,
        "170000",
    )
    original_message = f"migration failed for {TEST_DATABASE_URL}"
    monkeypatch.setattr(
        conftest.command, "upgrade", Mock(side_effect=RuntimeError(original_message))
    )
    fixture_function = conftest.postgres_migrated_engine._fixture_function

    with pytest.raises(RuntimeError) as error:
        fixture_function(engine)

    assert original_message not in str(error.value)
    assert TEST_DATABASE_URL not in str(error.value)
    assert "fixture-secret" not in str(error.value)
    assert error.value.__suppress_context__
