"""Alembic environment for the SignalForge metadata database.

Two things differ from the stock template:

* The URL comes from :class:`signalforge.config.Settings`, so migrations and the
  running services always target the same database. ``-x url=...`` overrides it
  for one-off runs against another environment.
* ``render_as_batch`` is enabled for SQLite. SQLite cannot ``ALTER COLUMN`` or
  add a constraint in place, so Alembic rebuilds the table instead; without
  this, every migration that touches an existing column fails on the
  development/test database while passing on PostgreSQL.
"""

from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# The library lives in libs/signalforge; make it importable when alembic is
# invoked from the repository root.
REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_PATH = REPO_ROOT / "libs" / "signalforge"
if str(LIB_PATH) not in sys.path:
    sys.path.insert(0, str(LIB_PATH))

from signalforge.config import get_settings  # noqa: E402
from signalforge.storage.db import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """``-x url=...`` beats the environment, which beats the default."""
    forced = context.get_x_argument(as_dictionary=True).get("url")
    if forced:
        return forced
    return get_settings().database_url


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (``alembic upgrade head --sql``)."""
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=_is_sqlite(url),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # When invoked programmatically (signalforge.storage.db.upgrade_database)
    # the caller hands us a live connection so the migration runs on the same
    # engine the application already opened, rather than dialling a second one.
    injected = config.attributes.get("connection")
    if injected is not None:
        context.configure(
            connection=injected,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=injected.engine.url.get_backend_name() == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    url = _database_url()
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=_is_sqlite(url),
        )
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
