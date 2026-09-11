"""Case management, the state machine, approval gating and the audit trail."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from signalforge.incidents import IncidentError, IncidentManager
from signalforge.models.alert import Alert, AlertStatus
from signalforge.models.incident import IncidentStatus, TimelineEntry
from signalforge.response import LabAdapter, ResponseError, ResponseService, list_playbooks
from signalforge.response.service import STATUS_EXECUTED, STATUS_PENDING, STATUS_REJECTED

pytestmark = pytest.mark.integration

BASE = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)


def make_alert(**overrides) -> Alert:
    payload = {
        "tenant": "acme",
        "rule_id": "sf-idn-0001",
        "rule_title": "Unexpected Privilege Grant",
        "rule_level": "high",
        "risk_score": 74,
        "risk_level": "high",
        "principal": "alex@example.com",
        "source_ip": "10.0.4.82",
        "hostname": "web-01",
        "tactics": ["privilege_escalation"],
        "techniques": ["T1098.003"],
        "first_seen": BASE,
        "last_seen": BASE,
        "event_ids": ["event-1"],
    }
    payload.update(overrides)
    return Alert(**payload)


@pytest.fixture
def incidents(session_factory, event_store, settings) -> IncidentManager:
    return IncidentManager(session_factory, event_store, settings)


@pytest.fixture
def responses(session_factory, settings, incidents) -> ResponseService:
    return ResponseService(
        session_factory, settings=settings, incidents=incidents, adapter=LabAdapter(settings)
    )


# ------------------------------------------------------------------ alerts ---
def test_alert_upsert_merges_repeats(incidents: IncidentManager) -> None:
    alert = make_alert()
    stored, created = incidents.record_alert(alert)
    assert created and stored.occurrences == 1

    repeat = make_alert(event_ids=["event-2"], last_seen=BASE + timedelta(minutes=1))
    merged, created_again = incidents.record_alert(repeat)
    assert not created_again
    assert merged.occurrences == 2
    assert set(merged.event_ids) == {"event-1", "event-2"}
    assert len(incidents.list_alerts("acme")) == 1


def test_building_blocks_stay_out_of_the_analyst_queue(
    ruleset, event_store, session_factory, settings
) -> None:
    """A correlation building block is stored, but does not bury the queue."""
    from signalforge.lab import TelemetryGenerator
    from signalforge.pipeline import Pipeline

    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)
    generator = TelemetryGenerator(tenant="acme", seed=21)

    # 400 ordinary events: mostly successful logons, which is the building block.
    pipeline.ingest(generator.normal_activity(400, BASE, spread_seconds=3600))

    queue = incidents.list_alerts("acme", limit=500)
    everything = incidents.list_alerts("acme", include_building_blocks=True, limit=500)

    assert everything, "the building-block alerts must still be recorded"
    assert len(queue) < len(everything), "the queue must be smaller than the raw set"
    assert all(not alert.is_building_block for alert in queue)
    assert any(alert.rule_id == "sf-auth-0002" for alert in everything)
    assert not any(alert.rule_id == "sf-auth-0002" for alert in queue)

    # They are also kept out of the "noisiest rules" tuning list and the counts.
    assert all(row["rule_id"] != "sf-auth-0002" for row in incidents.top_rules("acme"))
    counts = incidents.counts("acme")
    assert counts["alerts_building_blocks"] > 0
    assert counts["alerts_total"] == len(queue)


def test_alert_status_change_is_audited(incidents: IncidentManager) -> None:
    stored, _ = incidents.record_alert(make_alert())
    updated = incidents.set_alert_status(
        "acme", stored.alert_id, AlertStatus.FALSE_POSITIVE, "analyst@acme.io", "known change"
    )
    assert updated.status == AlertStatus.FALSE_POSITIVE
    actions = [entry["action"] for entry in incidents.audit_trail("acme")]
    assert "alert.status_changed" in actions


# --------------------------------------------------------------- incidents ---
def test_single_high_risk_alert_opens_an_incident(incidents: IncidentManager) -> None:
    alert, _ = incidents.record_alert(make_alert(risk_score=88))
    incident = incidents.open_from_alert(alert)
    assert incident is not None
    assert incident.key.startswith("INC-")
    assert incident.severity.value == "high"
    assert incident.status == IncidentStatus.NEW


def test_low_risk_alert_does_not_open_an_incident(incidents: IncidentManager) -> None:
    alert, _ = incidents.record_alert(make_alert(risk_score=22, risk_level="informational"))
    assert incidents.open_from_alert(alert) is None
    assert incidents.open_from_alert(alert, force=True) is not None


def test_incident_keys_increment_per_tenant(incidents: IncidentManager) -> None:
    first = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    second = incidents.open_from_alert(
        make_alert(risk_score=80, principal="dana@example.com"), force=True
    )
    other_tenant = incidents.open_from_alert(make_alert(risk_score=80, tenant="globex"), force=True)
    assert first.key != second.key
    assert int(second.key.split("-")[1]) == int(first.key.split("-")[1]) + 1
    assert other_tenant.key == first.key, "each tenant has its own sequence"


def test_repeat_detection_extends_the_same_incident(incidents: IncidentManager) -> None:
    first = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    second = incidents.open_from_alert(
        make_alert(risk_score=85, last_seen=BASE + timedelta(minutes=5)), force=True
    )
    assert second.incident_id == first.incident_id
    assert second.risk_score == 85
    assert len(incidents.list("acme")) == 1


# ----------------------------------------------------------- state machine ---
def test_valid_transitions_are_audited(incidents: IncidentManager) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    reference = incident.key

    triaged = incidents.transition("acme", reference, IncidentStatus.TRIAGED, "analyst@acme.io")
    assert triaged.status == IncidentStatus.TRIAGED

    investigating = incidents.transition(
        "acme", reference, IncidentStatus.INVESTIGATING, "analyst@acme.io"
    )
    assert investigating.status == IncidentStatus.INVESTIGATING

    resolved = incidents.transition(
        "acme", reference, IncidentStatus.RESOLVED, "analyst@acme.io", "handled"
    )
    assert resolved.status == IncidentStatus.RESOLVED
    assert resolved.closed_at is not None
    assert resolved.close_reason == "handled"

    actions = [entry["action"] for entry in incidents.audit_trail("acme", reference)]
    assert actions.count("incident.status_changed") == 3


def test_illegal_transition_is_rejected(incidents: IncidentManager) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    with pytest.raises(IncidentError):
        # NEW -> CONTAINED is not a legal step.
        incidents.transition("acme", incident.key, IncidentStatus.CONTAINED, "analyst@acme.io")


def test_unknown_incident_raises(incidents: IncidentManager) -> None:
    with pytest.raises(IncidentError):
        incidents.transition("acme", "INC-9999", IncidentStatus.TRIAGED, "analyst@acme.io")


def test_notes_and_assignment(incidents: IncidentManager) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    assigned = incidents.assign("acme", incident.key, "dana@example.com", "admin@acme.io")
    assert assigned.owner == "dana@example.com"

    noted = incidents.add_note("acme", incident.key, "dana@example.com", "Checked the VPN logs.")
    assert noted.notes[-1].body == "Checked the VPN logs."
    assert any(entry.kind == "note" for entry in noted.timeline)

    with pytest.raises(IncidentError):
        incidents.add_note("acme", incident.key, "dana@example.com", "   ")


def test_correlated_chain_supersedes_its_single_alert_incidents(
    ruleset, event_store, session_factory, settings
) -> None:
    """One intrusion is one case, not one case per stage."""
    from signalforge.lab import TelemetryGenerator
    from signalforge.pipeline import Pipeline

    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)
    generator = TelemetryGenerator(tenant="acme", seed=7)

    pipeline.ingest(generator.account_compromise(BASE))

    everything = incidents.list("acme", limit=50)
    chain = next(i for i in everything if i.scenario == "account_compromise")
    assert chain.is_open
    assert len(chain.alert_ids) == 4

    # The stage-level incidents opened before the chain completed are closed
    # with a pointer to the case that replaced them.
    superseded = [i for i in everything if (i.close_reason or "").startswith("Superseded")]
    assert superseded, "expected the chain to absorb its stage incidents"
    assert all(i.status == IncidentStatus.RESOLVED for i in superseded)
    assert any(chain.key in (i.close_reason or "") for i in superseded)

    open_incidents = incidents.list("acme", open_only=True, limit=50)
    assert chain.key in [i.key for i in open_incidents]
    assert len(open_incidents) < len(everything)

    audit = [entry["action"] for entry in incidents.audit_trail("acme")]
    assert "incident.superseded" in audit


def test_incident_with_its_own_evidence_is_not_superseded(incidents: IncidentManager) -> None:
    """An incident that still owns alerts of its own stays open."""
    first, _ = incidents.record_alert(make_alert(risk_score=80))
    second, _ = incidents.record_alert(
        make_alert(
            risk_score=80, rule_id="sf-cloud-0002", rule_title="Cloud Audit Logging Disabled"
        )
    )
    standalone = incidents.open_from_alert(first, force=True)
    incidents.open_from_alert(second, force=True)

    # A later, unrelated incident links only the second alert - the first
    # incident keeps its own evidence and must remain open.
    refreshed = incidents.get("acme", standalone.key)
    assert refreshed.is_open


def test_closed_incident_that_recurs_opens_a_new_one(incidents: IncidentManager) -> None:
    first = incidents.open_from_alert(make_alert(risk_score=80), force=True)
    incidents.transition("acme", first.key, IncidentStatus.TRIAGED, "analyst@acme.io")
    incidents.transition(
        "acme",
        first.key,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
        "analyst@acme.io",
        "expected change",
    )

    recurrence = incidents.open_from_alert(
        make_alert(risk_score=80, last_seen=BASE + timedelta(minutes=10)), force=True
    )
    assert recurrence.incident_id != first.incident_id
    assert len(incidents.list("acme")) == 2


def test_timeline_merges_alerts_events_and_entries(incidents: IncidentManager, event_store) -> None:
    from signalforge.models.ocsf import RawLogRecord
    from signalforge.normalize import normalize

    events = [
        normalize(
            RawLogRecord(
                source="linux.sshd",
                tenant="acme",
                raw="Sep 10 13:4%d:00 web-01 sshd[%d]: Failed password for alex "
                "from 10.0.4.82 port %d ssh2" % (index, index, 40000 + index),
            )
        )
        for index in range(3)
    ]
    event_store.index(events)

    alert, _ = incidents.record_alert(make_alert(event_ids=[e.sf_event_id for e in events]))
    incident = incidents.open_from_alert(alert, force=True)
    incidents.append_timeline(
        "acme",
        incident.key,
        TimelineEntry(
            time=BASE + timedelta(minutes=10),
            kind="note",
            title="Analyst checked",
            actor="dana",
        ),
    )

    timeline = incidents.build_timeline("acme", incident.key)
    kinds = {entry.kind for entry in timeline}
    assert {"alert", "event", "note"}.issubset(kinds)
    times = [entry.time for entry in timeline]
    assert times == sorted(times)


def test_counts_summarise_the_queue(incidents: IncidentManager) -> None:
    incidents.record_alert(make_alert(risk_score=95, risk_level="critical"))
    incidents.record_alert(
        make_alert(risk_score=75, risk_level="high", principal="dana@example.com")
    )
    incidents.open_from_alert(make_alert(risk_score=95, risk_level="critical"), force=True)

    counts = incidents.counts("acme")
    assert counts["alerts_total"] == 2
    assert counts["alerts_critical"] == 1
    assert counts["alerts_high"] == 1
    assert counts["incidents_open"] == 1


# ------------------------------------------------------------- the response --
def test_playbook_catalogue_is_documented() -> None:
    playbooks = {playbook["name"]: playbook for playbook in list_playbooks()}
    assert "contain_account" in playbooks
    assert playbooks["contain_account"]["approver_roles"] == ["admin"]
    assert all(playbook["description"] for playbook in playbooks.values())


def test_response_requires_approval_and_four_eyes(
    incidents: IncidentManager, responses: ResponseService
) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=88), force=True)

    action = responses.request(
        tenant="acme",
        playbook="revoke_sessions",
        actor="analyst@acme.io",
        incident_id=incident.key,
    )
    assert action["status"] == STATUS_PENDING
    assert action["target"] == "alex@example.com"  # suggested from the incident
    assert action["dry_run"] is True

    # The requester cannot approve their own action.
    with pytest.raises(ResponseError):
        responses.approve(
            tenant="acme", action_id=action["id"], actor="analyst@acme.io", role="responder"
        )

    # Nor can a role without the privilege.
    with pytest.raises(ResponseError):
        responses.approve(
            tenant="acme", action_id=action["id"], actor="viewer@acme.io", role="viewer"
        )

    executed = responses.approve(
        tenant="acme", action_id=action["id"], actor="responder@acme.io", role="responder"
    )
    assert executed["status"] == STATUS_EXECUTED
    assert executed["result"]["dry_run"] is True
    assert "would revoke" in executed["result"]["message"]


def test_composite_playbook_needs_an_admin(
    incidents: IncidentManager, responses: ResponseService
) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=92), force=True)
    action = responses.request(
        tenant="acme",
        playbook="contain_account",
        actor="analyst@acme.io",
        incident_id=incident.key,
    )
    with pytest.raises(ResponseError):
        responses.approve(
            tenant="acme", action_id=action["id"], actor="responder@acme.io", role="responder"
        )
    executed = responses.approve(
        tenant="acme", action_id=action["id"], actor="admin@acme.io", role="admin"
    )
    assert executed["status"] == STATUS_EXECUTED
    assert len(executed["result"]["data"]["steps"]) == 3


def test_rejected_action_never_executes(
    incidents: IncidentManager, responses: ResponseService
) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=88), force=True)
    action = responses.request(
        tenant="acme", playbook="deny_ip", actor="analyst@acme.io", incident_id=incident.key
    )
    rejected = responses.reject(
        tenant="acme", action_id=action["id"], actor="responder@acme.io", reason="known VPN"
    )
    assert rejected["status"] == STATUS_REJECTED
    with pytest.raises(ResponseError):
        responses.run(tenant="acme", action_id=action["id"], actor="responder@acme.io")


def test_playbook_target_validation(incidents: IncidentManager, responses: ResponseService) -> None:
    incident = incidents.open_from_alert(
        make_alert(risk_score=88, source_ip=None, hostname=None), force=True
    )
    with pytest.raises(ResponseError):
        responses.request(
            tenant="acme", playbook="deny_ip", actor="analyst@acme.io", incident_id=incident.key
        )
    with pytest.raises(ResponseError):
        responses.request(
            tenant="acme",
            playbook="not_a_playbook",
            actor="analyst@acme.io",
            incident_id=incident.key,
        )


def test_live_mode_writes_to_the_local_denylist(
    incidents: IncidentManager, session_factory, settings, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "response_dry_run", False)
    monkeypatch.setattr(settings, "response_denylist_path", str(tmp_path / "denylist.txt"))
    service = ResponseService(
        session_factory, settings=settings, incidents=incidents, adapter=LabAdapter(settings)
    )
    incident = incidents.open_from_alert(make_alert(risk_score=90), force=True)

    action = service.request(
        tenant="acme", playbook="deny_ip", actor="analyst@acme.io", incident_id=incident.key
    )
    executed = service.approve(
        tenant="acme", action_id=action["id"], actor="responder@acme.io", role="responder"
    )
    assert executed["status"] == STATUS_EXECUTED
    assert executed["result"]["dry_run"] is False
    assert service.adapter.read_denylist() == ["10.0.4.82"]


def test_response_actions_appear_on_the_incident_timeline(
    incidents: IncidentManager, responses: ResponseService
) -> None:
    incident = incidents.open_from_alert(make_alert(risk_score=88), force=True)
    action = responses.request(
        tenant="acme", playbook="revoke_sessions", actor="analyst@acme.io", incident_id=incident.key
    )
    responses.approve(
        tenant="acme", action_id=action["id"], actor="responder@acme.io", role="responder"
    )

    refreshed = incidents.get("acme", incident.key)
    kinds = [entry.kind for entry in refreshed.timeline]
    assert kinds.count("response") >= 3  # requested, approved, executed
    actions = [entry["action"] for entry in incidents.audit_trail("acme")]
    assert "response.requested" in actions
    assert "response.approved" in actions
    assert "response.executed" in actions
