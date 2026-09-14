"""Multi-analyst operations: queues, claiming, transfer and who may do what.

The behaviour these cover is the difference between a detection engine and
something a shift can actually work: an incident lands in a queue, a person
takes it, somebody else cannot silently take it from them, moving it between
teams leaves a reason behind, and closing it needs the right authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.auth import AuthService
from signalforge.incidents import (
    IncidentConflict,
    IncidentError,
    IncidentManager,
    IncidentPermissionError,
    TeamError,
    TeamService,
)
from signalforge.models.alert import Alert
from signalforge.models.incident import IncidentStatus
from signalforge.models.team import normalise_slug

pytestmark = pytest.mark.integration

BASE = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)
TENANT = "acme"


@pytest.fixture
def incidents(session_factory, event_store, settings) -> IncidentManager:
    return IncidentManager(session_factory, event_store, settings)


@pytest.fixture
def teams(session_factory) -> TeamService:
    return TeamService(session_factory)


@pytest.fixture
def users(session_factory, settings) -> AuthService:
    auth = AuthService(session_factory, settings)
    auth.ensure_tenant(TENANT, "Acme")
    for email, role in (
        ("dana@acme.test", "analyst"),
        ("sam@acme.test", "analyst"),
        ("rio@acme.test", "responder"),
        ("boss@acme.test", "admin"),
    ):
        auth.create_user(tenant=TENANT, email=email, password="correct horse battery", role=role)
    return auth


def user_id(users: AuthService, email: str) -> str:
    principal = users.authenticate(tenant=TENANT, email=email, password="correct horse battery")
    return principal["user"]["id"] if isinstance(principal, dict) else principal.user_id


@pytest.fixture
def incident(incidents: IncidentManager):
    """One high-risk incident, opened the way the correlator would open it."""
    alert = Alert(
        tenant=TENANT,
        rule_id="sf-idn-0001",
        rule_title="Unexpected Privilege Grant",
        rule_level="high",
        risk_score=88,
        risk_level="high",
        principal="alex@example.com",
        source_ip="10.0.4.82",
        tactics=["privilege_escalation"],
        first_seen=BASE,
        last_seen=BASE,
        event_ids=["event-1"],
    )
    incidents.record_alert(alert)
    opened = incidents.open_from_alert(alert, force=True)
    assert opened is not None
    return opened


# --------------------------------------------------------------------- teams
def test_slugs_are_normalised() -> None:
    assert normalise_slug("Cloud Security") == "cloud-security"
    assert normalise_slug("  SOC  ") == "soc"
    with pytest.raises(ValueError):
        normalise_slug("   ")


def test_create_and_list_teams(teams: TeamService) -> None:
    teams.create(TENANT, "Cloud Security", description="Cloud estate")
    teams.create(TENANT, "Identity")

    listed = teams.list(TENANT)
    assert [team.slug for team in listed] == ["cloud-security", "identity"]

    with pytest.raises(TeamError, match="already exists"):
        teams.create(TENANT, "Cloud Security")


def test_a_tenant_has_exactly_one_default_queue(teams: TeamService) -> None:
    first = teams.ensure_default(TENANT)
    assert first.is_default

    # Calling again returns the same queue rather than making a second one.
    assert teams.ensure_default(TENANT).id == first.id

    cloud = teams.create(TENANT, "Cloud Security")
    teams.set_default(TENANT, cloud.slug)

    defaults = [team.slug for team in teams.list(TENANT) if team.is_default]
    assert defaults == ["cloud-security"], "the old default must be demoted"


def test_membership_and_lead_authority(teams: TeamService, users: AuthService) -> None:
    team = teams.create(TENANT, "Identity")
    teams.add_member(TENANT, team.slug, "dana@acme.test", role="lead")
    teams.add_member(TENANT, team.slug, "sam@acme.test")

    loaded = teams.require(TENANT, team.slug)
    assert {m.email for m in loaded.members} == {"dana@acme.test", "sam@acme.test"}
    assert [m.email for m in loaded.leads] == ["dana@acme.test"]

    dana = user_id(users, "dana@acme.test")
    sam = user_id(users, "sam@acme.test")
    assert teams.is_lead(TENANT, team.id, dana)
    assert not teams.is_lead(TENANT, team.id, sam)

    # Re-adding changes the role rather than duplicating the membership.
    teams.add_member(TENANT, team.slug, "sam@acme.test", role="lead")
    assert len(teams.require(TENANT, team.slug).members) == 2
    assert teams.is_lead(TENANT, team.id, sam)

    teams.remove_member(TENANT, team.slug, "sam@acme.test")
    assert {m.email for m in teams.require(TENANT, team.slug).members} == {"dana@acme.test"}


def test_unknown_user_cannot_be_added(teams: TeamService, users: AuthService) -> None:
    team = teams.create(TENANT, "Identity")
    with pytest.raises(TeamError, match="no such user"):
        teams.add_member(TENANT, team.slug, "ghost@acme.test")


def test_a_queue_with_open_work_cannot_be_deleted(
    teams: TeamService, incidents: IncidentManager, incident
) -> None:
    team = teams.create(TENANT, "Identity")
    incidents.route(TENANT, incident.key, team.id, team_slug=team.slug)

    with pytest.raises(TeamError, match="still owns"):
        teams.delete(TENANT, team.slug)


# ------------------------------------------------------------ claim / queue
def test_route_then_claim_then_queue_counts(
    teams: TeamService, incidents: IncidentManager, users: AuthService, incident
) -> None:
    team = teams.create(TENANT, "Identity")
    incidents.route(TENANT, incident.key, team.id, team_slug=team.slug)

    queued = teams.list(TENANT)[0]
    assert (queued.open_incidents, queued.unclaimed_incidents) == (1, 1)

    dana = user_id(users, "dana@acme.test")
    claimed = incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    assert claimed.owner == "dana@acme.test"
    assert claimed.assignee_id == dana
    assert claimed.acknowledged_at is not None, "claiming starts the MTTA clock"

    queued = teams.list(TENANT)[0]
    assert (queued.open_incidents, queued.unclaimed_incidents) == (1, 0)


def test_claiming_someone_elses_incident_is_a_conflict(
    incidents: IncidentManager, users: AuthService, incident
) -> None:
    dana = user_id(users, "dana@acme.test")
    sam = user_id(users, "sam@acme.test")
    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")

    with pytest.raises(IncidentConflict, match="already claimed"):
        incidents.claim(TENANT, incident.key, user_id=sam, email="sam@acme.test")

    # Re-claiming your own is a no-op, not an error.
    again = incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    assert again.owner == "dana@acme.test"

    # A lead reassigning after a shift ends can force it.
    forced = incidents.claim(TENANT, incident.key, user_id=sam, email="sam@acme.test", force=True)
    assert forced.owner == "sam@acme.test"


def test_unclaim_returns_it_to_the_queue_but_keeps_the_ack_clock(
    incidents: IncidentManager, users: AuthService, incident
) -> None:
    dana = user_id(users, "dana@acme.test")
    claimed = incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    acknowledged = claimed.acknowledged_at

    released = incidents.unclaim(
        TENANT, incident.key, actor="dana@acme.test", reason="end of shift"
    )
    assert released.assignee_id is None and released.owner is None
    assert released.acknowledged_at == acknowledged, "MTTA is measured from the first claim"


# ----------------------------------------------------------------- transfer
def test_transfer_requires_a_reason_and_records_it(
    teams: TeamService, incidents: IncidentManager, users: AuthService, incident
) -> None:
    identity = teams.create(TENANT, "Identity")
    cloud = teams.create(TENANT, "Cloud Security")
    incidents.route(TENANT, incident.key, identity.id, team_slug=identity.slug)
    dana = user_id(users, "dana@acme.test")
    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")

    with pytest.raises(IncidentError, match="needs a reason"):
        incidents.transfer(
            TENANT,
            incident.key,
            team_id=cloud.id,
            team_slug=cloud.slug,
            reason="  ",
            actor="dana@acme.test",
        )

    moved = incidents.transfer(
        TENANT,
        incident.key,
        team_id=cloud.id,
        team_slug=cloud.slug,
        reason="the credential was an IAM key, not an app token",
        actor="dana@acme.test",
    )
    assert moved.team_id == cloud.id
    assert moved.assignee_id is None, "the receiving team claims it themselves"

    trail = incidents.audit_trail(TENANT, reference=incident.key)
    transfer_entries = [entry for entry in trail if entry["action"] == "incident.transferred"]
    assert len(transfer_entries) == 1
    assert "IAM key" in transfer_entries[0]["detail"]


def test_transfer_to_the_same_team_is_rejected(
    teams: TeamService, incidents: IncidentManager, incident
) -> None:
    identity = teams.create(TENANT, "Identity")
    incidents.route(TENANT, incident.key, identity.id, team_slug=identity.slug)
    with pytest.raises(IncidentError, match="already with"):
        incidents.transfer(
            TENANT,
            incident.key,
            team_id=identity.id,
            team_slug=identity.slug,
            reason="no-op",
            actor="dana@acme.test",
        )


# ------------------------------------------------------- concurrent editing
def test_a_stale_version_is_rejected(
    incidents: IncidentManager, users: AuthService, incident
) -> None:
    dana = user_id(users, "dana@acme.test")
    stale_version = incident.version

    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")

    # Sam loaded the incident before Dana claimed it and now tries to act.
    with pytest.raises(IncidentConflict, match="moved on since you loaded it"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.TRIAGED,
            actor="sam@acme.test",
            expected_version=stale_version,
        )

    current = incidents.get(TENANT, incident.key)
    assert current.version == stale_version + 1

    # With the current version it goes through.
    updated = incidents.transition(
        TENANT,
        incident.key,
        IncidentStatus.TRIAGED,
        actor="sam@acme.test",
        expected_version=current.version,
    )
    assert updated.status is IncidentStatus.TRIAGED
    assert updated.version == current.version + 1


# ----------------------------------------------------------- authorisation
def test_containment_needs_a_responder(
    incidents: IncidentManager, users: AuthService, incident
) -> None:
    dana = user_id(users, "dana@acme.test")
    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    incidents.transition(TENANT, incident.key, IncidentStatus.TRIAGED, actor="dana@acme.test")
    incidents.transition(TENANT, incident.key, IncidentStatus.INVESTIGATING, actor="dana@acme.test")

    with pytest.raises(IncidentPermissionError, match="needs the responder role"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.CONTAINED,
            actor="dana@acme.test",
            actor_role="analyst",
        )

    contained = incidents.transition(
        TENANT,
        incident.key,
        IncidentStatus.CONTAINED,
        actor="rio@acme.test",
        actor_role="responder",
    )
    assert contained.status is IncidentStatus.CONTAINED


def test_closing_as_a_false_positive_needs_admin_or_a_team_lead(
    teams: TeamService, incidents: IncidentManager, users: AuthService, incident
) -> None:
    team = teams.create(TENANT, "Identity")
    incidents.route(TENANT, incident.key, team.id, team_slug=team.slug)
    dana = user_id(users, "dana@acme.test")
    sam = user_id(users, "sam@acme.test")
    incidents.claim(TENANT, incident.key, user_id=sam, email="sam@acme.test")

    # A plain analyst may not write off a real detection as noise.
    with pytest.raises(IncidentPermissionError, match="needs the admin role"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.CLOSED_FALSE_POSITIVE,
            actor="sam@acme.test",
            actor_role="analyst",
            actor_user_id=sam,
            reason="looks benign",
        )

    # The lead of the owning team may, without holding tenant-wide admin.
    teams.add_member(TENANT, team.slug, "dana@acme.test", role="lead")
    closed = incidents.transition(
        TENANT,
        incident.key,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
        actor="dana@acme.test",
        actor_role="analyst",
        actor_user_id=dana,
        reason="scheduled access review, confirmed with the owner",
    )
    assert closed.status is IncidentStatus.CLOSED_FALSE_POSITIVE
    assert closed.close_reason.startswith("scheduled access review")


def test_a_queued_incident_must_be_claimed_before_closing(
    teams: TeamService, incidents: IncidentManager, incident
) -> None:
    team = teams.create(TENANT, "Identity")
    incidents.route(TENANT, incident.key, team.id, team_slug=team.slug)
    incidents.transition(TENANT, incident.key, IncidentStatus.TRIAGED, actor="dana@acme.test")

    with pytest.raises(IncidentError, match="nobody has claimed it"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.RESOLVED,
            actor="dana@acme.test",
            reason="done",
        )


# -------------------------------------------------------------- waiting state
def test_waiting_needs_a_wake_up_time_and_a_reason(incidents: IncidentManager, incident) -> None:
    incidents.transition(TENANT, incident.key, IncidentStatus.TRIAGED, actor="dana@acme.test")

    with pytest.raises(IncidentError, match="wake-up time"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.WAITING,
            actor="dana@acme.test",
            reason="waiting on the account owner",
        )

    wake = datetime.now(tz=timezone.utc) + timedelta(hours=4)
    with pytest.raises(IncidentError, match="needs a reason"):
        incidents.transition(
            TENANT,
            incident.key,
            IncidentStatus.WAITING,
            actor="dana@acme.test",
            waiting_until=wake,
        )

    parked = incidents.transition(
        TENANT,
        incident.key,
        IncidentStatus.WAITING,
        actor="dana@acme.test",
        reason="waiting on the account owner",
        waiting_until=wake,
    )
    assert parked.status is IncidentStatus.WAITING
    assert parked.waiting_reason == "waiting on the account owner"
    assert parked.is_open, "a parked incident is still open work"


def test_the_worker_can_find_incidents_whose_timer_expired(
    incidents: IncidentManager, incident
) -> None:
    incidents.transition(TENANT, incident.key, IncidentStatus.TRIAGED, actor="dana@acme.test")
    wake = datetime.now(tz=timezone.utc) + timedelta(hours=4)
    incidents.transition(
        TENANT,
        incident.key,
        IncidentStatus.WAITING,
        actor="dana@acme.test",
        reason="vendor ticket",
        waiting_until=wake,
    )

    assert incidents.due_for_wake_up(TENANT) == []

    later = wake + timedelta(minutes=1)
    due = incidents.due_for_wake_up(TENANT, now=later)
    assert [item.key for item in due] == [incident.key]

    # Coming back out of waiting clears the timer.
    resumed = incidents.transition(
        TENANT, incident.key, IncidentStatus.INVESTIGATING, actor="dana@acme.test"
    )
    assert resumed.waiting_until is None and resumed.waiting_reason is None
    assert incidents.due_for_wake_up(TENANT, now=later) == []
