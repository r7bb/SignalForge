"""Notification recipients, delivery, suppression and retry.

The rule that matters most: nobody is notified about their own action. A
channel that tells you what you just did is a channel that gets muted, and a
muted channel is worse than none.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.auth import AuthService
from signalforge.incidents import IncidentManager, TeamService
from signalforge.models.alert import Alert
from signalforge.notify import (
    MAX_ATTEMPTS,
    DeliveryStatus,
    MemoryChannel,
    NotificationKind,
    NotificationService,
)

pytestmark = pytest.mark.integration

TENANT = "acme"
BASE = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def channel() -> MemoryChannel:
    return MemoryChannel()


@pytest.fixture
def notifier(session_factory, settings, channel) -> NotificationService:
    return NotificationService(session_factory, settings, channels=[channel])


@pytest.fixture
def incidents(session_factory, event_store, settings, notifier) -> IncidentManager:
    manager = IncidentManager(session_factory, event_store, settings)
    # Inject the memory-channel notifier so the manager's own events are
    # observable instead of only being logged.
    manager._notifier = notifier
    return manager


@pytest.fixture
def teams(session_factory) -> TeamService:
    service = TeamService(session_factory)
    service.create(TENANT, "SOC Triage", is_default=True)
    service.create(TENANT, "Identity")
    return service


@pytest.fixture
def users(session_factory, settings) -> AuthService:
    auth = AuthService(session_factory, settings)
    auth.ensure_tenant(TENANT, "Acme")
    for email in ("dana@acme.test", "sam@acme.test", "rio@acme.test", "lead@acme.test"):
        auth.create_user(tenant=TENANT, email=email, password="correct horse", role="analyst")
    return auth


def uid(users: AuthService, email: str) -> str:
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


# -------------------------------------------------------------- recipients
def test_a_mention_notifies_exactly_the_person_named(incidents, incident, users, channel) -> None:
    dana = uid(users, "dana@acme.test")
    uid(users, "sam@acme.test")
    incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "@sam please confirm", author_id=dana
    )
    assert [n.recipient_email for n in channel.sent] == ["sam@acme.test"]
    assert channel.sent[0].kind is NotificationKind.MENTIONED
    assert incident.key in channel.sent[0].subject


def test_the_actor_is_never_notified_about_their_own_action(
    incidents, incident, users, channel
) -> None:
    """Mentioning yourself should not send you a message."""
    dana = uid(users, "dana@acme.test")
    incidents.add_comment(
        TENANT, incident.key, "dana@acme.test", "note to self @dana", author_id=dana
    )
    assert [n.recipient_email for n in channel.sent] == []


def test_watchers_hear_about_a_transfer_and_the_receiving_lead_does_too(
    incidents, incident, users, teams, channel
) -> None:
    dana = uid(users, "dana@acme.test")
    lead = uid(users, "lead@acme.test")
    teams.add_member(TENANT, "identity", "lead@acme.test", role="lead")
    identity = teams.require(TENANT, "identity")

    # Sam is watching; Dana does the transfer and should not be told. Start it
    # in the triage queue so the move to identity is a real transfer.
    incidents.watch(
        TENANT, incident.key, user_id=uid(users, "sam@acme.test"), email="sam@acme.test"
    )
    triage = teams.require(TENANT, "soc-triage")
    incidents.route(TENANT, incident.key, triage.id, team_slug=triage.slug)
    channel.clear()

    incidents.transfer(
        TENANT,
        incident.key,
        team_id=identity.id,
        team_slug="identity",
        reason="identity owns the credential",
        actor="dana@acme.test",
    )
    told = sorted(n.recipient_email for n in channel.sent)
    assert "sam@acme.test" in told, "a watcher hears about it"
    assert "lead@acme.test" in told, "the receiving lead hears about it"
    assert "dana@acme.test" not in told, "the person who did it does not"
    assert lead and dana  # names used


def test_an_sla_breach_notifies_the_assignee(incidents, incident, users, channel) -> None:
    dana = uid(users, "dana@acme.test")
    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    channel.clear()

    later = incident.created_at + timedelta(hours=12)
    incidents.escalate_sla_breach(TENANT, incident.key, now=later)

    told = [n.recipient_email for n in channel.sent]
    assert told == ["dana@acme.test"]
    assert channel.sent[0].kind is NotificationKind.SLA_BREACHED
    assert channel.sent[0].urgent, "a breach should be able to interrupt someone"


def test_nothing_is_sent_for_an_unknown_incident(notifier, channel) -> None:
    report = notifier.notify(TENANT, "INC-9999", NotificationKind.MENTIONED, "subject", "body")
    assert report.considered == 0 and channel.sent == []


# ---------------------------------------------------------------- delivery
def test_delivery_is_recorded_against_the_notification(notifier, incident, users) -> None:
    notifier.notify(
        TENANT,
        incident.key,
        NotificationKind.INCIDENT_CLOSED,
        "closed",
        "body",
        explicit=["sam@acme.test"],
    )
    pending = notifier.pending(TENANT)
    assert len(pending) == 1
    assert pending[0]["status"] == DeliveryStatus.SENT.value
    assert pending[0]["attempts"] == 1
    assert pending[0]["sent_at"] is not None


def test_with_no_channels_notifications_are_suppressed_not_left_pending(
    session_factory, settings, incident, users
) -> None:
    """A row stuck pending forever is a retry that can never succeed."""
    silent = NotificationService(session_factory, settings, channels=[])
    report = silent.notify(
        TENANT,
        incident.key,
        NotificationKind.MENTIONED,
        "subject",
        "body",
        explicit=["sam@acme.test"],
    )
    assert report.suppressed == 1
    assert silent.pending(TENANT)[0]["status"] == DeliveryStatus.SUPPRESSED.value


def test_notifications_can_be_switched_off(monkeypatch, session_factory, incident, users) -> None:
    monkeypatch.setenv("SIGNALFORGE_NOTIFY_ENABLED", "false")
    from signalforge.config import get_settings, reset_settings_cache

    reset_settings_cache()
    channel = MemoryChannel()
    service = NotificationService(session_factory, get_settings(), channels=[channel])
    report = service.notify(
        TENANT, incident.key, NotificationKind.MENTIONED, "s", "b", explicit=["sam@acme.test"]
    )
    assert report.considered == 0 and channel.sent == []
    reset_settings_cache()


# ------------------------------------------------------------------- retry
def test_a_failed_delivery_is_retried_after_its_backoff(
    session_factory, settings, incident, users
) -> None:
    channel = MemoryChannel(fail_on="flaky")
    service = NotificationService(session_factory, settings, channels=[channel])
    service.notify(
        TENANT,
        incident.key,
        NotificationKind.MENTIONED,
        "flaky subject",
        "body",
        explicit=["sam@acme.test"],
    )
    assert service.pending(TENANT)[0]["status"] == DeliveryStatus.FAILED.value
    assert "configured to fail" in service.pending(TENANT)[0]["last_error"]

    # Straight away, the backoff has not elapsed.
    assert service.retry_failed(TENANT).considered == 0

    # Once it has, and the channel has recovered, it goes out.
    channel.fail_on = None
    later = datetime.now(tz=timezone.utc) + timedelta(minutes=5)
    report = service.retry_failed(TENANT, now=later)
    assert report.sent == 1
    assert service.pending(TENANT)[0]["status"] == DeliveryStatus.SENT.value


def test_retry_gives_up_after_the_attempt_limit(session_factory, settings, incident, users) -> None:
    """Retrying forever turns the table into a queue nobody drains."""
    channel = MemoryChannel(fail_on="doomed")
    service = NotificationService(session_factory, settings, channels=[channel])
    service.notify(
        TENANT,
        incident.key,
        NotificationKind.MENTIONED,
        "doomed subject",
        "body",
        explicit=["sam@acme.test"],
    )

    now = datetime.now(tz=timezone.utc)
    for _ in range(MAX_ATTEMPTS + 3):
        now += timedelta(hours=1)
        service.retry_failed(TENANT, now=now)

    record = service.pending(TENANT)[0]
    assert record["status"] == DeliveryStatus.FAILED.value
    assert record["attempts"] == MAX_ATTEMPTS, "stops at the limit rather than climbing forever"


def test_a_failing_channel_does_not_break_the_operation(
    session_factory, event_store, settings, users, incident
) -> None:
    """The work happened; only the telling failed."""
    channel = MemoryChannel(fail_on="mentioned you")
    manager = IncidentManager(session_factory, event_store, settings)
    manager._notifier = NotificationService(session_factory, settings, channels=[channel])

    dana = uid(users, "dana@acme.test")
    updated, mentions = manager.add_comment(
        TENANT, incident.key, "dana@acme.test", "@sam look", author_id=dana
    )
    # The comment is there and the mention resolved, despite delivery failing.
    assert mentions.resolved == ["sam@acme.test"]
    assert len(manager.comments(TENANT, incident.key)) == 1
    assert updated.key == incident.key
