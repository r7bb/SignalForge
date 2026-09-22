"""Presence tracking.

Presence is worthless thirty seconds later, which is why it expires rather
than being stored. These tests drive the in-process backend; the Redis path is
the same logic against a shared hash.
"""

from __future__ import annotations

import time

import pytest
from signalforge.incidents.presence import DEFAULT_TTL_SECONDS, PresenceTracker

TENANT = "acme"
KEY = "INC-2001"


@pytest.fixture
def tracker(settings) -> PresenceTracker:
    # No redis_url in the test settings, so this is the in-process backend.
    return PresenceTracker(settings, ttl_seconds=2)


def test_the_test_settings_use_the_in_process_backend(tracker) -> None:
    assert tracker.backend == "memory"


def test_a_viewer_appears_after_announcing(tracker) -> None:
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    viewers = tracker.viewers(TENANT, KEY)
    assert [viewer.email for viewer in viewers] == ["dana@acme.test"]
    assert viewers[0].idle_seconds >= 0


def test_the_caller_can_be_excluded(tracker) -> None:
    """The question is who *else* is looking."""
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    tracker.announce(TENANT, KEY, email="sam@acme.test", user_id="u2")

    others = tracker.viewers(TENANT, KEY, exclude="dana@acme.test")
    assert [viewer.email for viewer in others] == ["sam@acme.test"]


def test_viewers_are_scoped_per_incident_and_tenant(tracker) -> None:
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    assert tracker.viewers(TENANT, "INC-2002") == []
    assert tracker.viewers("other-tenant", KEY) == []


def test_a_heartbeat_refreshes_rather_than_duplicating(tracker) -> None:
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    time.sleep(0.05)
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    assert len(tracker.viewers(TENANT, KEY)) == 1


def test_a_viewer_expires_once_the_ttl_passes(tracker) -> None:
    """A closed tab should stop being a phantom viewer."""
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    assert len(tracker.viewers(TENANT, KEY)) == 1

    time.sleep(2.1)  # ttl is 2s for this fixture
    assert tracker.viewers(TENANT, KEY) == []


def test_leaving_removes_the_viewer_immediately(tracker) -> None:
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    tracker.announce(TENANT, KEY, email="sam@acme.test", user_id="u2")

    tracker.leave(TENANT, KEY, email="dana@acme.test")
    assert [viewer.email for viewer in tracker.viewers(TENANT, KEY)] == ["sam@acme.test"]


def test_leaving_when_not_present_is_not_an_error(tracker) -> None:
    tracker.leave(TENANT, KEY, email="nobody@acme.test")
    assert tracker.viewers(TENANT, KEY) == []


def test_viewers_are_ordered_by_how_recently_they_were_seen(tracker) -> None:
    tracker.announce(TENANT, KEY, email="old@acme.test", user_id="u1")
    time.sleep(0.2)
    tracker.announce(TENANT, KEY, email="new@acme.test", user_id="u2")

    assert [viewer.email for viewer in tracker.viewers(TENANT, KEY)] == [
        "new@acme.test",
        "old@acme.test",
    ]


def test_sweep_drops_expired_entries(tracker) -> None:
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    assert tracker.sweep() == 0, "nothing expired yet"

    # Sweep with a clock far enough ahead that the entry has aged out.
    dropped = tracker.sweep(now=time.time() + 60)
    assert dropped == 1
    assert tracker.viewers(TENANT, KEY) == []


def test_the_default_ttl_is_short_enough_to_be_useful() -> None:
    """Presence that lingers for minutes is worse than none: it lies."""
    assert 10 <= DEFAULT_TTL_SECONDS <= 60


def test_a_broken_redis_url_falls_back_instead_of_failing(monkeypatch, settings) -> None:
    """Presence is cosmetic; it must never stop the API serving incidents."""
    monkeypatch.setenv("SIGNALFORGE_REDIS_URL", "redis://127.0.0.1:1/0")
    from signalforge.config import get_settings, reset_settings_cache

    reset_settings_cache()
    tracker = PresenceTracker(get_settings())
    assert tracker.backend == "memory"
    tracker.announce(TENANT, KEY, email="dana@acme.test", user_id="u1")
    assert len(tracker.viewers(TENANT, KEY)) == 1
    reset_settings_cache()
