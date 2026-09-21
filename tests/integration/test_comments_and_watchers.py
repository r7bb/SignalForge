"""Threaded comments, mentions, and the watch list.

Watching and owning are deliberately different things: being mentioned in an
incident puts you on the notification list without making it your case.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from signalforge.auth import AuthService
from signalforge.incidents import IncidentError, IncidentManager
from signalforge.models.alert import Alert

pytestmark = pytest.mark.integration

TENANT = "acme"
BASE = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def incidents(session_factory, event_store, settings) -> IncidentManager:
    return IncidentManager(session_factory, event_store, settings)


@pytest.fixture
def users(session_factory, settings) -> AuthService:
    auth = AuthService(session_factory, settings)
    auth.ensure_tenant(TENANT, "Acme")
    for email in ("dana@acme.test", "sam@acme.test", "rio@acme.test"):
        auth.create_user(tenant=TENANT, email=email, password="correct horse", role="analyst")
    return auth


def user_id(users: AuthService, email: str) -> str:
    principal = users.authenticate(tenant=TENANT, email=email, password="correct horse")
    return principal["user"]["id"] if isinstance(principal, dict) else principal.user_id


@pytest.fixture
def incident(incidents: IncidentManager):
    alert = Alert(
        tenant=TENANT,
        rule_id="sf-idn-0001",
        rule_title="Unexpected Privilege Grant",
        rule_level="high",
        risk_score=88,
        risk_level="high",
        principal="alex@example.com",
        tactics=["privilege_escalation"],
        first_seen=BASE,
        last_seen=BASE,
        event_ids=["event-1"],
    )
    incidents.record_alert(alert)
    opened = incidents.open_from_alert(alert, force=True)
    assert opened is not None
    return opened


# ---------------------------------------------------------------- comments
def test_a_comment_is_stored_and_shows_in_the_thread(incidents, incident, users) -> None:
    dana = user_id(users, "dana@acme.test")
    incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "Source is a known Tor exit.", author_id=dana
    )

    threads = incidents.comments(TENANT, incident.key)
    assert len(threads) == 1
    assert threads[0]["author"] == "dana@acme.test"
    assert threads[0]["replies"] == []
    assert threads[0]["created_at"].tzinfo is not None


def test_replies_nest_under_their_parent_in_order(incidents, incident, users) -> None:
    dana = user_id(users, "dana@acme.test")
    sam = user_id(users, "sam@acme.test")
    _, _ = incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "Is this in the change calendar?", author_id=dana
    )
    parent = incidents.comments(TENANT, incident.key)[0]

    incidents.add_comment(
        TENANT,
        incident.key,
        "sam@acme.test",
        "No - I checked.",
        author_id=sam,
        parent_id=parent["id"],
    )
    incidents.add_comment(
        TENANT,
        incident.key,
        "dana@acme.test",
        "Then treat it as compromise.",
        author_id=dana,
        parent_id=parent["id"],
    )
    # A second top-level comment stays top-level.
    incidents.add_comment(TENANT, incident.key, "sam@acme.test", "Separate point.", author_id=sam)

    threads = incidents.comments(TENANT, incident.key)
    assert len(threads) == 2, "two top-level comments"
    assert [reply["body"] for reply in threads[0]["replies"]] == [
        "No - I checked.",
        "Then treat it as compromise.",
    ]
    assert threads[1]["replies"] == []


def test_an_empty_comment_is_rejected(incidents, incident) -> None:
    with pytest.raises(IncidentError, match="cannot be empty"):
        incidents.add_comment(TENANT, incident.key, "dana@acme.test", "   ")


def test_replying_to_a_comment_on_another_incident_is_rejected(incidents, incident, users) -> None:
    """A reply has to belong to the thread it claims to be in."""
    dana = user_id(users, "dana@acme.test")
    incidents.add_comment(TENANT, incident.key, "dana@acme.test", "first", author_id=dana)

    with pytest.raises(IncidentError, match="not a comment on"):
        incidents.add_comment(
            TENANT, incident.key, "dana@acme.test", "reply", parent_id="does-not-exist"
        )


def test_the_legacy_note_helper_still_works(incidents, incident) -> None:
    """add_note predates comments and is still called by the /notes route."""
    updated = incidents.add_note(TENANT, incident.key, "dana@acme.test", "plain note")
    assert any(note.body == "plain note" for note in updated.notes)
    assert len(incidents.comments(TENANT, incident.key)) == 1


# ---------------------------------------------------------------- mentions
def test_a_mention_resolves_and_adds_a_watcher(incidents, incident, users) -> None:
    dana = user_id(users, "dana@acme.test")
    _, mentions = incidents.add_comment(
        TENANT,
        incident.key,
        "dana@acme.test",
        "@sam can you confirm the role change?",
        author_id=dana,
    )
    assert mentions.resolved == ["sam@acme.test"]

    watching = {
        watcher["email"]: watcher["reason"] for watcher in incidents.watchers(TENANT, incident.key)
    }
    assert watching["sam@acme.test"] == "mentioned"
    # The author is watching too, but for their own reason.
    assert watching["dana@acme.test"] == "manual"


def test_being_mentioned_does_not_assign_the_incident(incidents, incident, users) -> None:
    """The distinction the whole design rests on."""
    dana = user_id(users, "dana@acme.test")
    incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "@sam take a look", author_id=dana
    )
    current = incidents.get(TENANT, incident.key)
    assert current.assignee_id is None
    assert current.owner is None


def test_an_unresolved_mention_is_reported_back(incidents, incident, users) -> None:
    dana = user_id(users, "dana@acme.test")
    _, mentions = incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "@ghost please advise", author_id=dana
    )
    assert mentions.resolved == []
    assert mentions.unresolved == ["ghost"]
    # And nobody was added to the watch list for it.
    assert [w["email"] for w in incidents.watchers(TENANT, incident.key)] == ["dana@acme.test"]


def test_mentions_are_recorded_on_the_comment_and_in_the_audit(incidents, incident, users) -> None:
    dana = user_id(users, "dana@acme.test")
    incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "@sam and @rio - see this", author_id=dana
    )
    thread = incidents.comments(TENANT, incident.key)[0]
    assert sorted(thread["mentions"]) == ["rio@acme.test", "sam@acme.test"]

    trail = incidents.audit_trail(TENANT, reference=incident.key)
    notes = [entry for entry in trail if entry["action"] == "incident.note_added"]
    assert sorted(notes[0]["data"]["mentions"]) == ["rio@acme.test", "sam@acme.test"]


# ---------------------------------------------------------------- watchers
def test_watch_and_unwatch(incidents, incident, users) -> None:
    sam = user_id(users, "sam@acme.test")
    watchers = incidents.watch(TENANT, incident.key, user_id=sam, email="sam@acme.test")
    assert [w["email"] for w in watchers] == ["sam@acme.test"]

    # Watching twice changes nothing.
    again = incidents.watch(TENANT, incident.key, user_id=sam, email="sam@acme.test")
    assert len(again) == 1

    remaining = incidents.unwatch(TENANT, incident.key, user_id=sam)
    assert remaining == []


def test_unwatching_when_not_watching_is_not_an_error(incidents, incident, users) -> None:
    rio = user_id(users, "rio@acme.test")
    assert incidents.unwatch(TENANT, incident.key, user_id=rio) == []


def test_a_mention_does_not_downgrade_an_existing_manual_watch(incidents, incident, users) -> None:
    """Somebody who chose to watch should not be relabelled by a mention."""
    dana = user_id(users, "dana@acme.test")
    sam = user_id(users, "sam@acme.test")
    incidents.watch(TENANT, incident.key, user_id=sam, email="sam@acme.test", reason="manual")

    incidents.add_comment(TENANT, incident.key, "dana@acme.test", "@sam ping", author_id=dana)
    watching = {w["email"]: w["reason"] for w in incidents.watchers(TENANT, incident.key)}
    assert watching["sam@acme.test"] == "manual", "the earlier deliberate watch wins"


def test_watchers_are_scoped_to_the_incident(incidents, incident, users, session_factory) -> None:
    second = Alert(
        tenant=TENANT,
        rule_id="sf-cloud-0001",
        rule_title="Cloud Console Login Without MFA",
        rule_level="high",
        risk_score=80,
        risk_level="high",
        principal="other@example.com",
        first_seen=BASE,
        last_seen=BASE,
        event_ids=["event-2"],
        dedup_key="second",
    )
    incidents.record_alert(second)
    other = incidents.open_from_alert(second, force=True)

    sam = user_id(users, "sam@acme.test")
    incidents.watch(TENANT, incident.key, user_id=sam, email="sam@acme.test")
    assert incidents.watchers(TENANT, other.key) == []
