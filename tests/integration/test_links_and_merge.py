"""Case linking and merging.

One intrusion should be one case. The property a merge has to preserve is that
evidence *moves* rather than being copied: after it, every alert belongs to
exactly one incident and no count is double.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.incidents import IncidentError, IncidentManager
from signalforge.models.alert import Alert
from signalforge.models.incident import IncidentSeverity, IncidentStatus
from signalforge.models.link import LinkRelationship

pytestmark = pytest.mark.integration

TENANT = "acme"
BASE = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def incidents(session_factory, event_store, settings) -> IncidentManager:
    return IncidentManager(session_factory, event_store, settings)


def open_incident(incidents: IncidentManager, *, dedup: str, risk: int = 88, **extra):
    payload = {
        "tenant": TENANT,
        "rule_id": "sf-idn-0001",
        "rule_title": "Unexpected Privilege Grant",
        "rule_level": "high",
        "risk_score": risk,
        "risk_level": "critical" if risk >= 90 else "high",
        "principal": "user-%s@example.com" % dedup,
        "source_ip": "10.0.4.%d" % (abs(hash(dedup)) % 200 + 1),
        "hostname": "host-%s" % dedup,
        "tactics": ["privilege_escalation"],
        "techniques": ["T1098"],
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


# ------------------------------------------------------------------- links
def test_a_symmetric_link_reads_the_same_from_both_ends(incidents) -> None:
    first = open_incident(incidents, dedup="a")
    second = open_incident(incidents, dedup="b")

    incidents.link(
        TENANT,
        first.key,
        second.key,
        LinkRelationship.RELATED_TO,
        actor="dana@acme.test",
        reason="same source address",
    )

    from_first = incidents.links(TENANT, first.key)
    from_second = incidents.links(TENANT, second.key)
    assert [link["other_key"] for link in from_first] == [second.key]
    assert [link["other_key"] for link in from_second] == [first.key]
    assert from_first[0]["relationship"] == "related_to"
    assert from_second[0]["relationship"] == "related_to", "symmetric reads the same way"


def test_a_symmetric_link_is_stored_once(incidents) -> None:
    """Linking back the other way must not create a second edge."""
    first = open_incident(incidents, dedup="a")
    second = open_incident(incidents, dedup="b")

    incidents.link(TENANT, first.key, second.key, LinkRelationship.RELATED_TO)
    incidents.link(TENANT, second.key, first.key, LinkRelationship.RELATED_TO)

    assert len(incidents.links(TENANT, first.key)) == 1
    assert len(incidents.links(TENANT, second.key)) == 1


def test_a_directional_link_reads_differently_from_each_end(incidents) -> None:
    cause = open_incident(incidents, dedup="cause")
    effect = open_incident(incidents, dedup="effect")

    incidents.link(TENANT, effect.key, cause.key, LinkRelationship.CAUSED_BY)

    assert incidents.links(TENANT, effect.key)[0]["relationship"] == "caused_by"
    # From the other end it is not "caused_by" pointing backwards.
    assert incidents.links(TENANT, cause.key)[0]["relationship"] == "led_to"


def test_an_incident_cannot_be_linked_to_itself(incidents) -> None:
    only = open_incident(incidents, dedup="only")
    with pytest.raises(IncidentError, match="cannot be linked to itself"):
        incidents.link(TENANT, only.key, only.key, LinkRelationship.RELATED_TO)


def test_linking_to_an_unknown_incident_is_rejected(incidents) -> None:
    only = open_incident(incidents, dedup="only")
    with pytest.raises(IncidentError, match="unknown incident"):
        incidents.link(TENANT, only.key, "INC-9999", LinkRelationship.RELATED_TO)


def test_unlink_removes_the_edge_from_both_ends(incidents) -> None:
    first = open_incident(incidents, dedup="a")
    second = open_incident(incidents, dedup="b")
    incidents.link(TENANT, first.key, second.key, LinkRelationship.RELATED_TO)

    # Removing from the far end works too: it is one edge, not two.
    assert incidents.unlink(TENANT, second.key, first.key) == []
    assert incidents.links(TENANT, first.key) == []


def test_linking_is_audited(incidents) -> None:
    first = open_incident(incidents, dedup="a")
    second = open_incident(incidents, dedup="b")
    incidents.link(
        TENANT,
        first.key,
        second.key,
        LinkRelationship.RELATED_TO,
        actor="dana@acme.test",
        reason="same credential",
    )
    trail = incidents.audit_trail(TENANT, reference=first.key)
    linked = [entry for entry in trail if entry["action"] == "incident.linked"]
    assert len(linked) == 1
    assert linked[0]["data"]["other"] == second.key
    assert linked[0]["detail"] == "same credential"


# ------------------------------------------------------------------- merge
def test_merge_moves_the_evidence_and_closes_the_duplicate(incidents) -> None:
    survivor = open_incident(incidents, dedup="keep", risk=80)
    duplicate = open_incident(incidents, dedup="dup", risk=95)

    merged = incidents.merge(
        TENANT,
        keep=survivor.key,
        merge=duplicate.key,
        actor="rio@acme.test",
        reason="same intrusion, two detections",
    )

    # Evidence unioned onto the survivor.
    assert len(merged.alert_ids) == 2
    assert set(merged.event_ids) == {"event-keep", "event-dup"}
    assert "host-dup" in merged.hostnames and "host-keep" in merged.hostnames
    # And the merged case is at least as bad as its worst part.
    assert merged.risk_score == 95
    assert merged.severity is IncidentSeverity.CRITICAL

    # The duplicate is closed, pointing at where it went.
    closed = incidents.get(TENANT, duplicate.key)
    assert closed.status is IncidentStatus.RESOLVED
    assert closed.close_reason == "Merged into %s" % survivor.key


def test_merge_does_not_double_count_evidence(incidents) -> None:
    """The alerts move; they are not copied. Exactly one row each."""
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(incidents, dedup="dup")

    incidents.merge(TENANT, keep=survivor.key, merge=duplicate.key, actor="rio@acme.test")

    survivor_alerts = incidents.list_alerts(TENANT, incident_id=survivor.incident_id)
    duplicate_alerts = incidents.list_alerts(TENANT, incident_id=duplicate.incident_id)
    assert len(survivor_alerts) == 2
    assert duplicate_alerts == [], "the duplicate keeps no evidence of its own"

    # And the total alert count across the tenant has not grown.
    assert len(incidents.list_alerts(TENANT, limit=50)) == 2


def test_merge_records_a_duplicate_of_link(incidents) -> None:
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(incidents, dedup="dup")
    incidents.merge(TENANT, keep=survivor.key, merge=duplicate.key, actor="rio@acme.test")

    from_duplicate = incidents.links(TENANT, duplicate.key)
    assert [link["relationship"] for link in from_duplicate] == ["duplicate_of"]
    assert from_duplicate[0]["other_key"] == survivor.key

    # From the survivor's side, it reads as having been duplicated.
    from_survivor = incidents.links(TENANT, survivor.key)
    assert [link["relationship"] for link in from_survivor] == ["duplicated_by"]


def test_merge_widens_the_time_span(incidents) -> None:
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(
        incidents,
        dedup="dup",
        first_seen=BASE - timedelta(hours=3),
        last_seen=BASE + timedelta(hours=1),
    )
    merged = incidents.merge(TENANT, keep=survivor.key, merge=duplicate.key, actor="rio@acme.test")
    assert merged.first_seen <= BASE - timedelta(hours=3)
    assert merged.last_seen >= BASE + timedelta(hours=1)


def test_merging_an_incident_into_itself_is_rejected(incidents) -> None:
    only = open_incident(incidents, dedup="only")
    with pytest.raises(IncidentError, match="into itself"):
        incidents.merge(TENANT, keep=only.key, merge=only.key, actor="rio@acme.test")


def test_merging_an_already_closed_incident_is_rejected(incidents) -> None:
    """Closing is a decision somebody made; a merge must not bury it."""
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(incidents, dedup="dup")
    incidents.transition(TENANT, duplicate.key, IncidentStatus.TRIAGED, actor="dana@acme.test")
    incidents.transition(
        TENANT, duplicate.key, IncidentStatus.RESOLVED, actor="dana@acme.test", reason="handled"
    )

    with pytest.raises(IncidentError, match="already closed"):
        incidents.merge(TENANT, keep=survivor.key, merge=duplicate.key, actor="rio@acme.test")


def test_merge_is_audited_on_both_incidents(incidents) -> None:
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(incidents, dedup="dup")
    incidents.merge(
        TENANT,
        keep=survivor.key,
        merge=duplicate.key,
        actor="rio@acme.test",
        reason="one intrusion",
    )

    survivor_trail = incidents.audit_trail(TENANT, reference=survivor.key)
    assert any(entry["action"] == "incident.merged" for entry in survivor_trail)

    duplicate_trail = incidents.audit_trail(TENANT, reference=duplicate.key)
    assert any(entry["action"] == "incident.merged_away" for entry in duplicate_trail)


def test_merge_bumps_the_version_so_open_pages_notice(incidents) -> None:
    survivor = open_incident(incidents, dedup="keep")
    duplicate = open_incident(incidents, dedup="dup")
    before = survivor.version

    merged = incidents.merge(TENANT, keep=survivor.key, merge=duplicate.key, actor="rio@acme.test")
    assert merged.version > before
