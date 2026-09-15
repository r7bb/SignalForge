"""Auto-routing: a new incident lands in the queue its rules name.

The important negative case is the last one: routing runs on creation only, so
an analyst's transfer is not undone the next time an alert joins the incident.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.incidents import IncidentManager, TeamService
from signalforge.models.alert import Alert

pytestmark = pytest.mark.integration

BASE = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)
TENANT = "acme"

ROUTING = """
id: route-identity
team: identity
priority: 10
match:
  tactic: [credential_access, privilege_escalation]
---
id: route-cloud
team: cloud-security
priority: 20
match:
  scenario: [cloud_persistence]
---
id: route-critical-endpoint
team: endpoint
priority: 5
match:
  tactic: [collection]
  min_risk: 90
---
id: route-fallback
team: soc-triage
priority: 9000
"""


@pytest.fixture
def routing_dir(tmp_path, monkeypatch):
    directory = tmp_path / "routing"
    directory.mkdir()
    (directory / "rules.yml").write_text(ROUTING)
    monkeypatch.setenv("SIGNALFORGE_ROUTING_PATH", str(directory))

    from signalforge.config import reset_settings_cache

    reset_settings_cache()
    yield directory
    reset_settings_cache()


@pytest.fixture
def incidents(session_factory, event_store, routing_dir) -> IncidentManager:
    from signalforge.config import get_settings

    return IncidentManager(session_factory, event_store, get_settings())


@pytest.fixture
def teams(session_factory) -> TeamService:
    service = TeamService(session_factory)
    for name, default in (
        ("SOC Triage", True),
        ("Identity", False),
        ("Cloud Security", False),
        ("Endpoint", False),
    ):
        service.create(TENANT, name, is_default=default)
    return service


def make_alert(**overrides) -> Alert:
    payload = {
        "tenant": TENANT,
        "rule_id": "sf-idn-0001",
        "rule_title": "Unexpected Privilege Grant",
        "rule_level": "high",
        "risk_score": 88,
        "risk_level": "high",
        "principal": "alex@example.com",
        "source_ip": "10.0.4.82",
        "tactics": ["privilege_escalation"],
        "first_seen": BASE,
        "last_seen": BASE,
        "event_ids": ["event-1"],
    }
    payload.update(overrides)
    return Alert(**payload)


def open_incident(incidents: IncidentManager, alert: Alert):
    incidents.record_alert(alert)
    opened = incidents.open_from_alert(alert, force=True)
    assert opened is not None
    return opened


def test_a_new_incident_is_routed_by_tactic(incidents, teams) -> None:
    incident = open_incident(incidents, make_alert())
    assert incident.team_slug == "identity"

    # And the decision is audited with the rule that made it.
    trail = incidents.audit_trail(TENANT, reference=incident.key)
    routed = [entry for entry in trail if entry["action"] == "incident.routed"]
    assert routed, "routing must be auditable"
    assert routed[0]["data"]["rule"] == "route-identity"


def test_priority_decides_between_overlapping_rules(incidents, teams) -> None:
    """collection + risk>=90 is priority 5, so it beats the priority-10 rule."""
    incident = open_incident(
        incidents,
        make_alert(
            rule_id="sf-app-0001",
            dedup_key="collection-high",
            tactics=["collection", "credential_access"],
            risk_score=95,
            risk_level="critical",
        ),
    )
    assert incident.team_slug == "endpoint"


def test_a_rule_that_does_not_match_on_risk_falls_through(incidents, teams) -> None:
    incident = open_incident(
        incidents,
        make_alert(
            rule_id="sf-app-0002",
            dedup_key="collection-low",
            tactics=["collection"],
            risk_score=72,
            risk_level="high",
        ),
    )
    # min_risk 90 excluded the endpoint rule, and nothing else matches
    # "collection", so the catch-all took it.
    assert incident.team_slug == "soc-triage"


def test_an_unknown_team_in_a_rule_falls_back_to_the_default_queue(
    incidents, teams, routing_dir, session_factory, event_store
) -> None:
    """A rule naming a queue that does not exist must not lose the incident."""
    (routing_dir / "rules.yml").write_text("id: route-ghost\nteam: does-not-exist\npriority: 1\n")
    from signalforge.config import get_settings

    fresh = IncidentManager(session_factory, event_store, get_settings())
    incident = open_incident(fresh, make_alert(dedup_key="ghost-route"))
    assert incident.team_slug == "soc-triage", "must land in the default queue, not nowhere"


def test_with_no_queues_configured_an_incident_is_left_unrouted(incidents) -> None:
    incident = open_incident(incidents, make_alert(dedup_key="no-teams"))
    assert incident.team_id is None and incident.team_slug is None


def test_routing_can_be_switched_off(
    monkeypatch, teams, session_factory, event_store, routing_dir
) -> None:
    monkeypatch.setenv("SIGNALFORGE_ROUTING_ENABLED", "false")
    from signalforge.config import get_settings, reset_settings_cache

    reset_settings_cache()
    manager = IncidentManager(session_factory, event_store, get_settings())
    incident = open_incident(manager, make_alert(dedup_key="routing-off"))
    assert incident.team_id is None


def test_routing_does_not_override_a_manual_transfer(incidents, teams) -> None:
    """The point of a transfer is that it sticks."""
    incident = open_incident(incidents, make_alert())
    assert incident.team_slug == "identity"

    cloud = teams.require(TENANT, "cloud-security")
    incidents.transfer(
        TENANT,
        incident.key,
        team_id=cloud.id,
        team_slug=cloud.slug,
        reason="the credential was an IAM key, not an app token",
        actor="dana@acme.test",
    )

    # A later alert joins the same incident; routing must not reclaim it.
    follow_up = make_alert(
        dedup_key="second-alert",
        event_ids=["event-2"],
        first_seen=BASE + timedelta(minutes=2),
        last_seen=BASE + timedelta(minutes=2),
    )
    incidents.record_alert(follow_up)
    incidents.open_from_alert(follow_up, force=True)

    current = incidents.get(TENANT, incident.key)
    assert current.team_slug == "cloud-security", "a transfer must survive later alerts"
