"""The Alembic chain and the ORM models must describe the same schema.

The test suite builds each throwaway database with ``create_all`` because it is
fast, which means the migrations are never exercised incidentally. These tests
are what stop the two drifting: add a column to a model without a migration and
``test_migrations_match_the_models`` fails with the missing operation named.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from signalforge.storage.db import Base, find_migrations_path, upgrade_database
from sqlalchemy import create_engine, inspect, text

pytestmark = pytest.mark.integration


def _alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(find_migrations_path()))
    return config


@pytest.fixture
def migrated_engine(tmp_path: Path):
    """A database built by running the migration chain from empty to head."""
    engine = create_engine("sqlite+pysqlite:///%s" % (tmp_path / "migrated.db"))
    upgrade_database(engine=engine)
    yield engine
    engine.dispose()


def test_migrations_match_the_models(migrated_engine) -> None:
    with migrated_engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={"compare_type": True, "render_as_batch": True},
        )
        diff = compare_metadata(context, Base.metadata)

    assert diff == [], (
        "the migrations and the models disagree - generate a revision with\n"
        "  alembic revision --autogenerate -m '<what changed>'\n"
        "outstanding operations: %s" % _describe(diff)
    )


def test_create_all_and_migrations_produce_the_same_tables(migrated_engine, tmp_path) -> None:
    """The two paths the codebase uses must land in the same place."""
    direct = create_engine("sqlite+pysqlite:///%s" % (tmp_path / "direct.db"))
    Base.metadata.create_all(direct)

    migrated_tables = set(inspect(migrated_engine).get_table_names()) - {"alembic_version"}
    direct_tables = set(inspect(direct).get_table_names())
    direct.dispose()

    assert migrated_tables == direct_tables

    for table in sorted(migrated_tables):
        migrated_columns = {c["name"] for c in inspect(migrated_engine).get_columns(table)}
        direct_columns = {c["name"] for c in inspect(direct).get_columns(table)}
        assert migrated_columns == direct_columns, "column drift in %r" % table


def test_downgrade_to_base_leaves_nothing_behind(migrated_engine) -> None:
    from alembic import command

    config = _alembic_config()
    with migrated_engine.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "base")

    remaining = set(inspect(migrated_engine).get_table_names()) - {"alembic_version"}
    assert remaining == set(), "downgrade left tables behind: %s" % sorted(remaining)


def test_upgrade_preserves_existing_rows(tmp_path) -> None:
    """A migration has to carry data forward, not just reshape empty tables.

    This is the case ``create_all`` cannot express and the one that caught a
    real bug: batch mode rebuilds the table on SQLite, so an unnamed constraint
    anywhere in the schema made the whole upgrade fail.
    """
    from alembic import command

    engine = create_engine("sqlite+pysqlite:///%s" % (tmp_path / "populated.db"))
    config = _alembic_config()

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")

    stamp = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc).isoformat()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO incidents (id, tenant, key, title, status, severity, owner,"
                " risk_score, dedup_key, first_seen, last_seen, tactics, techniques,"
                " payload, created_at, updated_at) VALUES (:id, :tenant, :key, :title,"
                " :status, :severity, :owner, :risk, :dedup, :ts, :ts, '[]', '[]', '{}',"
                " :ts, :ts)"
            ),
            {
                "id": "incident-1",
                "tenant": "acme",
                "key": "INC-2001",
                "title": "Pre-existing incident",
                "status": "investigating",
                "severity": "high",
                "owner": "alex@example.com",
                "risk": 84,
                "dedup": "dedup-1",
                "ts": stamp,
            },
        )

    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT key, title, risk_score, version, team_id FROM incidents")
        ).one()

    assert row.key == "INC-2001"
    assert row.title == "Pre-existing incident"
    assert row.risk_score == 84
    assert row.version == 1, "the new column must be back-filled, not left NULL"
    assert row.team_id is None, "an existing incident starts unrouted"

    # And the rollback keeps the row too.
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "0001")

    with engine.connect() as connection:
        assert connection.execute(text("SELECT key FROM incidents")).scalar() == "INC-2001"
        columns = {c["name"] for c in inspect(engine).get_columns("incidents")}
    assert "team_id" not in columns and "version" not in columns
    engine.dispose()


def test_the_chain_has_a_single_head() -> None:
    """Two heads mean an un-merged branch; upgrades would silently skip one."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, "expected one head, found %s - needs an alembic merge" % list(heads)


def test_every_revision_can_be_downgraded() -> None:
    """A revision without a real downgrade cannot be rolled back in an incident."""
    script = ScriptDirectory.from_config(_alembic_config())
    stubs = []
    for revision in script.walk_revisions():
        source = Path(revision.path).read_text(encoding="utf-8")
        body = source.split("def downgrade()", 1)[-1]
        if body.strip().endswith("pass") and len(body.strip().splitlines()) <= 3:
            stubs.append(revision.revision)
    assert stubs == [], "revisions with an empty downgrade(): %s" % stubs


def _describe(diff) -> str:
    return ", ".join(str(item[0]) if isinstance(item, tuple) else str(item) for item in diff)
