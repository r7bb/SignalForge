"""SLA clocks on real incidents, breach escalation, and the SOC report."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.auth import AuthService
from signalforge.incidents import IncidentManager, SocMetrics, TeamService
from signalforge.models.alert import Alert
from signalforge.models.incident import IncidentSeverity, IncidentStatus
from signalforge.sla import STATE_BREACHED, STATE_MET, STATE_OK

pytestmark = pytest.mark.integration

TENANT = "acme"
BASE = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def incidents(session_factory, event_store, settings) -> IncidentManager:
    return IncidentManager(session_factory, event_store, settings)


@pytest.fixture
def metrics(session_factory) -> SocMetrics:
    return SocMetrics(session_factory)


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
    auth.create_user(
        tenant=TENANT, email="dana@acme.test", password="correct horse", role="analyst"
    )
    return auth


def dana_id(users: AuthService) -> str:
    principal = users.authenticate(tenant=TENANT, email="dana@acme.test", password="correct horse")
    return principal["user"]["id"] if isinstance(principal, dict) else principal.user_id


def open_incident(incidents: IncidentManager, *, risk: int = 95, dedup: str = "d1", **extra):
    payload = {
        "tenant": TENANT,
        "rule_id": "sf-idn-0001",
        "rule_title": "Unexpected Privilege Grant",
        "rule_level": "critical",
        "risk_score": risk,
        "risk_level": "critical" if risk >= 90 else "high",
        # The incident dedup key is tenant|single|rule_id|principal|source_ip,
        # so a distinct principal per call is what keeps these separate cases
        # rather than one incident collecting every alert.
        "principal": "user-%s@example.com" % dedup,
        "tactics": ["privilege_escalation"],
        "first_seen": BASE,
        "last_seen": BASE,
        "event_ids": ["event-%s" % dedup],
        "dedup_key": dedup,
    }
    payload.update(extra)
    alert = Alert(**payload)
    incidents.record_alert(alert)
    opened = incidents.open_from_alert(alert, force=True)
    assert opened is not None
    return opened


# ------------------------------------------------------------------ clocks
def test_both_clocks_are_set_from_the_severity_when_an_incident_opens(incidents) -> None:
    incident = open_incident(incidents)
    assert incident.severity is IncidentSeverity.CRITICAL
    assert incident.sla_ack_due is not None and incident.sla_resolve_due is not None

    # Critical: 15 minutes to acknowledge, 240 to resolve.
    assert (incident.sla_ack_due - incident.created_at) == timedelta(minutes=15)
    assert (incident.sla_resolve_due - incident.created_at) == timedelta(minutes=240)
    assert incident.sla_resolve_due > incident.sla_ack_due


def test_a_lower_severity_gets_a_looser_clock(incidents) -> None:
    critical = open_incident(incidents, risk=95, dedup="crit")
    medium = open_incident(
        incidents, risk=55, dedup="med", rule_level="medium", risk_level="medium"
    )
    assert medium.severity is not IncidentSeverity.CRITICAL
    critical_window = critical.sla_ack_due - critical.created_at
    medium_window = medium.sla_ack_due - medium.created_at
    assert medium_window > critical_window


def test_the_clocks_survive_a_round_trip_through_the_database(incidents) -> None:
    opened = open_incident(incidents)
    reloaded = incidents.get(TENANT, opened.key)
    assert reloaded.sla_ack_due == opened.sla_ack_due
    assert reloaded.sla_resolve_due == opened.sla_resolve_due
    # Timezone-aware on the way back out, or arithmetic against now() raises.
    assert reloaded.sla_ack_due.tzinfo is not None


def test_claiming_stops_the_acknowledge_clock(incidents, users) -> None:
    incident = open_incident(incidents)
    before = incidents.sla_state(incident)
    assert before["acknowledge"]["state"] in (STATE_OK, "at_risk")

    incidents.claim(TENANT, incident.key, user_id=dana_id(users), email="dana@acme.test")
    after = incidents.sla_state(incidents.get(TENANT, incident.key))
    assert after["acknowledge"]["state"] == STATE_MET
    assert after["breached"] is False


def test_an_unclaimed_incident_breaches_once_its_clock_expires(incidents) -> None:
    incident = open_incident(incidents)
    later = incident.created_at + timedelta(minutes=20)  # past the 15 minute target
    state = incidents.sla_state(incident, now=later)
    assert state["acknowledge"]["state"] == STATE_BREACHED
    assert state["breached"] is True


# --------------------------------------------------------------- breaches
def test_breaches_are_listed_worst_risk_first(incidents) -> None:
    low = open_incident(incidents, risk=72, dedup="low-risk", rule_level="high", risk_level="high")
    high = open_incident(incidents, risk=98, dedup="high-risk")
    later = BASE + timedelta(days=1)

    breaches = incidents.sla_breaches(TENANT, now=later)
    keys = [item.key for item in breaches]
    assert set(keys) == {low.key, high.key}
    assert keys[0] == high.key, "worst risk first"


def test_a_claimed_incident_is_not_an_acknowledge_breach(incidents, users) -> None:
    incident = open_incident(incidents)
    incidents.claim(TENANT, incident.key, user_id=dana_id(users), email="dana@acme.test")
    # Just past the acknowledge target but well inside the resolve one.
    soon = incident.created_at + timedelta(minutes=20)
    assert incidents.sla_breaches(TENANT, now=soon) == []


def test_escalation_bumps_severity_once_and_is_audited(incidents) -> None:
    incident = open_incident(incidents, risk=75, dedup="esc", rule_level="high", risk_level="high")
    assert incident.severity is IncidentSeverity.HIGH
    later = incident.created_at + timedelta(hours=3)

    escalated = incidents.escalate_sla_breach(TENANT, incident.key, now=later)
    assert escalated is not None
    assert escalated.severity is IncidentSeverity.CRITICAL
    assert escalated.sla_escalated_at is not None

    trail = incidents.audit_trail(TENANT, reference=incident.key)
    breaches = [entry for entry in trail if entry["action"] == "incident.sla_breached"]
    assert len(breaches) == 1
    assert breaches[0]["data"]["to_severity"] == "critical"

    # Running again is a no-op: the worker is on a schedule and must not
    # re-escalate the same breach every cycle.
    assert (
        incidents.escalate_sla_breach(TENANT, incident.key, now=later + timedelta(hours=1)) is None
    )
    trail = incidents.audit_trail(TENANT, reference=incident.key)
    assert len([e for e in trail if e["action"] == "incident.sla_breached"]) == 1


def test_escalation_declines_when_nothing_is_breached(incidents) -> None:
    incident = open_incident(incidents)
    assert incidents.escalate_sla_breach(TENANT, incident.key, now=incident.created_at) is None


def test_critical_cannot_escalate_past_critical(incidents) -> None:
    incident = open_incident(incidents, risk=99, dedup="already-crit")
    later = incident.created_at + timedelta(days=1)
    escalated = incidents.escalate_sla_breach(TENANT, incident.key, now=later)
    assert escalated is not None
    assert escalated.severity is IncidentSeverity.CRITICAL


# ---------------------------------------------------------------- metrics
def test_the_report_measures_mtta_and_mttr(incidents, metrics, users, teams) -> None:
    dana = dana_id(users)
    identity = teams.require(TENANT, "identity")

    first = open_incident(incidents, dedup="m1")
    incidents.route(TENANT, first.key, identity.id, team_slug=identity.slug)
    incidents.claim(TENANT, first.key, user_id=dana, email="dana@acme.test")
    incidents.transition(TENANT, first.key, IncidentStatus.TRIAGED, actor="dana@acme.test")
    incidents.transition(
        TENANT, first.key, IncidentStatus.RESOLVED, actor="dana@acme.test", reason="handled"
    )

    # A second, still unclaimed and open.
    open_incident(incidents, dedup="m2", risk=80, rule_level="high", risk_level="high")

    report = metrics.report(TENANT, days=7)
    assert report["incidents_opened"] == 2
    assert report["incidents_closed"] == 1
    assert report["mtta"]["count"] == 1
    assert report["mtta"]["mean_seconds"] is not None
    assert report["mttr"]["resolved"]["count"] == 1
    assert report["mttr"]["false_positive"]["count"] == 0

    # Per-team and per-analyst breakdowns name the slug and the email.
    assert [entry["team"] for entry in report["by_team"]] == ["identity"]
    assert [entry["analyst"] for entry in report["by_analyst"]] == ["dana@acme.test"]

    # Queue age. Both incidents auto-route to identity (the shipped routing
    # table matches sf-idn-*), so that is the queue carrying the open work:
    # one open, still unclaimed, with a measurable age.
    queues = {entry["team"]: entry for entry in report["queues"]}
    assert "identity" in queues, "auto-routing should have placed the open incident"
    assert queues["identity"]["open"] == 1
    assert queues["identity"]["unclaimed"] == 1
    assert queues["identity"]["oldest_unclaimed_seconds"] is not None


def test_mttr_separates_false_positives_from_real_resolutions(
    incidents, metrics, users, teams
) -> None:
    """Averaging a two-minute false positive with a six-hour intrusion lies."""
    dana = dana_id(users)
    real = open_incident(incidents, dedup="real")
    noise = open_incident(incidents, dedup="noise", risk=72, rule_level="high", risk_level="high")

    for key in (real.key, noise.key):
        incidents.claim(TENANT, key, user_id=dana, email="dana@acme.test", force=True)
        incidents.transition(TENANT, key, IncidentStatus.TRIAGED, actor="dana@acme.test")

    incidents.transition(
        TENANT, real.key, IncidentStatus.RESOLVED, actor="boss", reason="contained"
    )
    incidents.transition(
        TENANT,
        noise.key,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
        actor="boss",
        reason="scheduled access review",
    )

    report = metrics.report(TENANT, days=7)
    assert report["mttr"]["resolved"]["count"] == 1
    assert report["mttr"]["false_positive"]["count"] == 1
    assert report["mttr"]["combined"]["count"] == 2


def test_reopen_rate_counts_incidents_leaving_a_terminal_state(incidents, metrics, users) -> None:
    dana = dana_id(users)
    incident = open_incident(incidents, dedup="reopen")
    incidents.claim(TENANT, incident.key, user_id=dana, email="dana@acme.test")
    incidents.transition(TENANT, incident.key, IncidentStatus.TRIAGED, actor="dana@acme.test")
    incidents.transition(
        TENANT, incident.key, IncidentStatus.RESOLVED, actor="dana@acme.test", reason="done"
    )
    baseline = metrics.report(TENANT, days=7)
    assert baseline["reopened"] == 0
    assert baseline["analyst_closures"] == 1

    incidents.transition(TENANT, incident.key, IncidentStatus.INVESTIGATING, actor="dana@acme.test")
    report = metrics.report(TENANT, days=7)
    assert report["reopened"] == 1
    # Divided by analyst closures, not by what is closed right now - the
    # incident has been reopened, so it is no longer closed at all.
    assert report["analyst_closures"] == 1
    assert report["reopen_rate"] == 1.0


def test_sla_attainment_is_reported(incidents, metrics, users) -> None:
    dana = dana_id(users)
    met = open_incident(incidents, dedup="met")
    incidents.claim(TENANT, met.key, user_id=dana, email="dana@acme.test")
    open_incident(incidents, dedup="missed")  # never claimed

    now = BASE + timedelta(days=1)
    report = metrics.report(TENANT, days=7, now=now)
    acknowledge = report["sla"]["acknowledge"]
    assert acknowledge["total"] == 2
    assert acknowledge["met"] == 1 and acknowledge["breached"] == 1
    assert acknowledge["attainment"] == 0.5


def test_an_empty_tenant_reports_zeroes_rather_than_crashing(metrics) -> None:
    report = metrics.report("nobody", days=7)
    assert report["incidents_opened"] == 0
    assert report["mtta"]["mean_seconds"] is None
    assert report["reopen_rate"] is None
    assert report["queues"] == []
