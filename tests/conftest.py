"""Shared fixtures.

Every test runs against the in-process backends (memory event store, memory
bus, SQLite) so the suite needs no Docker.  The same code paths run against
OpenSearch/Kafka/PostgreSQL in the integration compose stack.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: A Thursday, mid-afternoon UTC: inside business hours, so the risk model's
#: "off hours" modifier does not perturb the expected scores.
BASE_TIME = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force the in-process backends and an isolated database per test."""
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setenv("SIGNALFORGE_ENVIRONMENT", "test")
    monkeypatch.setenv("SIGNALFORGE_BUS_BACKEND", "memory")
    monkeypatch.setenv("SIGNALFORGE_EVENT_STORE_BACKEND", "memory")
    monkeypatch.setenv("SIGNALFORGE_DATABASE_URL", "sqlite+pysqlite:///%s" % (tmp_path / "sf.db"))
    # Throwaway database per test: build it straight from the models.
    # tests/integration/test_migrations.py separately proves the Alembic
    # chain produces exactly this schema.
    monkeypatch.setenv("SIGNALFORGE_DB_AUTO_MIGRATE", "false")
    monkeypatch.setenv("SIGNALFORGE_JWT_SECRET", "test-secret")
    monkeypatch.setenv("SIGNALFORGE_RESPONSE_DRY_RUN", "true")
    monkeypatch.setenv("SIGNALFORGE_INTEL_HTTP_ENABLED", "false")

    from signalforge.assets import reset_inventory_cache
    from signalforge.config import reset_settings_cache
    from signalforge.identity import reset_resolver_cache
    from signalforge.storage.bus import reset_bus
    from signalforge.storage.db import reset_db_state
    from signalforge.storage.events import reset_event_store

    reset_settings_cache()
    reset_inventory_cache()
    reset_resolver_cache()
    reset_event_store()
    reset_bus()
    reset_db_state()
    yield
    reset_settings_cache()
    reset_event_store()
    reset_bus()
    reset_db_state()


@pytest.fixture
def settings():
    from signalforge.config import get_settings

    return get_settings()


@pytest.fixture
def event_store():
    from signalforge.storage.events import InMemoryEventStore

    return InMemoryEventStore()


@pytest.fixture
def bus():
    from signalforge.storage.bus import InMemoryBus

    return InMemoryBus()


@pytest.fixture
def db_engine():
    from signalforge.storage.db import init_db

    return init_db(drop=True)


@pytest.fixture
def session_factory(db_engine):
    from signalforge.storage.db import get_session_factory

    return get_session_factory()


@pytest.fixture(scope="session")
def ruleset():
    """The real detection directory - tests run against shipped rules."""
    from signalforge.sigma import load_ruleset

    return load_ruleset(REPO_ROOT / "detections", strict=True)


@pytest.fixture
def engine(ruleset):
    from signalforge.detect import DetectionEngine

    return DetectionEngine(ruleset)


@pytest.fixture
def correlator(ruleset):
    from signalforge.correlate import CorrelationEngine

    return CorrelationEngine(ruleset)


@pytest.fixture
def base_time() -> datetime:
    return BASE_TIME
