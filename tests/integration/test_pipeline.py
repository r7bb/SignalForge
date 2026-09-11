"""End-to-end pipeline behaviour: the failure modes, not just the happy path."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest
from signalforge.incidents import IncidentManager
from signalforge.lab import TelemetryGenerator
from signalforge.models.ocsf import RawLogRecord
from signalforge.pipeline import Pipeline
from signalforge.storage.events import EventQuery

pytestmark = pytest.mark.integration

BASE = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)


@pytest.fixture
def pipeline(ruleset, event_store, session_factory, settings) -> Pipeline:
    incidents = IncidentManager(session_factory, event_store, settings)
    return Pipeline(
        ruleset, event_store, settings=settings, incidents=incidents, enrich_events=False
    )


def sshd_failures(count: int, *, user: str = "alex", start: datetime = BASE, step: int = 5) -> list:
    records = []
    for index in range(count):
        moment = start + timedelta(seconds=index * step)
        records.append(
            RawLogRecord(
                source="linux.sshd",
                tenant="acme",
                raw="%s web-01 sshd[%d]: Failed password for %s from 10.0.4.82 port %d ssh2"
                % (moment.strftime("%b %d %H:%M:%S"), 1000 + index, user, 50000 + index),
                received_at=moment,
            )
        )
    return records


# ------------------------------------------------------------- happy path ----
def test_full_chain_produces_an_incident(pipeline: Pipeline) -> None:
    generator = TelemetryGenerator(tenant="acme", seed=7)
    result = pipeline.ingest(generator.account_compromise(BASE))

    assert result.counts["events"] > 0
    fired = {alert.rule_id for alert in result.alerts}
    assert "sf-auth-0001" in fired  # repeated failures
    assert "sf-idn-0001" in fired  # privilege grant
    assert "sf-cred-0001" in fired  # credential created
    assert any(hit.correlation.id == "sf-corr-0003" for hit in result.hits)

    incidents = [incident for incident in result.incidents if incident.scenario]
    assert incidents, "the correlated chain should open an incident"
    incident = max(incidents, key=lambda item: item.risk_score)
    assert incident.risk_score >= 70
    assert incident.key.startswith("INC-")
    assert "credential_access" in incident.tactics
    assert "persistence" in incident.tactics


def test_dlq_captures_unmappable_records(pipeline: Pipeline) -> None:
    result = pipeline.ingest(
        [
            RawLogRecord(source="windows.security", tenant="acme", payload={"EventID": 4625}),
            RawLogRecord(
                source="linux.sshd",
                tenant="acme",
                raw="Sep 10 13:00:00 web-01 chronyd[1]: clock stepped",
            ),
        ]
    )
    assert result.counts["events"] == 0
    assert result.counts["dlq"] == 2
    assert all(reason for _, reason in result.dlq)


# --------------------------------------------------------------- dedup -------
def test_duplicate_records_are_deduplicated(pipeline: Pipeline, event_store) -> None:
    records = sshd_failures(6)

    first = pipeline.ingest(records)
    assert first.index_result.indexed == 6
    assert first.index_result.duplicates == 0

    # The same batch redelivered (at-least-once) must not create new events...
    second = pipeline.ingest(records)
    assert second.index_result.indexed == 0
    assert second.index_result.duplicates == 6
    assert event_store.search(EventQuery(tenant="acme")).total == 6

    # ...and must not inflate the count-based detection either.
    assert pipeline.engine.stats.events_deduped == 6
    assert not second.alerts


def test_repeat_alert_becomes_one_row_with_occurrences(
    pipeline: Pipeline, session_factory, settings, event_store
) -> None:
    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline.ingest(sshd_failures(6))
    # A second burst for the same principal, outside the dedup window.
    pipeline.ingest(sshd_failures(6, start=BASE + timedelta(hours=2), step=5))

    alerts = incidents.list_alerts("acme", rule_id="sf-auth-0001")
    assert len(alerts) == 1, "same rule + same entity is one alert row"
    assert alerts[0].occurrences >= 2


def test_incident_is_deduplicated_when_a_detection_fires_twice(
    pipeline: Pipeline, session_factory, settings, event_store
) -> None:
    incidents = IncidentManager(session_factory, event_store, settings)
    generator = TelemetryGenerator(tenant="acme", seed=11)

    pipeline.ingest(generator.audit_tampering(BASE))
    pipeline.reset()  # forget suppression, as a restarted detector would
    pipeline.ingest(generator.audit_tampering(BASE + timedelta(minutes=2)))

    matching = [
        incident
        for incident in incidents.list("acme")
        if "Audit Logging" in incident.title or "audit" in (incident.scenario or "")
    ]
    assert len(matching) == 1, "the same detection and entity should extend one incident"


# ------------------------------------------------------------- ordering ------
def test_out_of_order_arrival_still_builds_the_right_timeline(
    pipeline: Pipeline, session_factory, settings, event_store
) -> None:
    generator = TelemetryGenerator(tenant="acme", seed=3)
    records = generator.account_compromise(BASE)
    shuffled = list(records)
    random.Random(42).shuffle(shuffled)

    pipeline.ingest(shuffled)

    events = event_store.timeline("acme", principals=["alex@example.com"], size=100)
    times = [event.time for event in events]
    assert times == sorted(times), "the timeline must be ordered by event time"
    assert len(events) == len(records)


def test_late_arriving_event_lands_in_the_right_slot(pipeline: Pipeline, event_store) -> None:
    pipeline.ingest(sshd_failures(3, start=BASE + timedelta(minutes=5)))
    pipeline.ingest(sshd_failures(1, start=BASE))  # arrives last, happened first

    events = event_store.timeline("acme", principals=["alex@example.com"], size=10)
    assert events[0].time == BASE


# ------------------------------------------------------- suppression / FP ----
def test_load_test_account_is_suppressed_end_to_end(pipeline: Pipeline) -> None:
    result = pipeline.ingest(sshd_failures(12, user="loadtest"))
    assert not result.alerts
    assert pipeline.engine.stats.alerts_suppressed > 0


def test_machine_account_filter_keeps_the_queue_clean(pipeline: Pipeline) -> None:
    result = pipeline.ingest(sshd_failures(12, user="backup$"))
    assert "sf-auth-0001" not in {alert.rule_id for alert in result.alerts}


# ------------------------------------------------------------ tenancy --------
def test_events_and_alerts_are_tenant_scoped(
    ruleset, session_factory, settings, event_store
) -> None:
    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)

    for tenant in ("acme", "globex"):
        records = [
            RawLogRecord(
                source="linux.sshd",
                tenant=tenant,
                raw="%s web-01 sshd[%d]: Failed password for alex from 10.0.4.82 port %d ssh2"
                % (
                    (BASE + timedelta(seconds=index * 5)).strftime("%b %d %H:%M:%S"),
                    index,
                    40000 + index,
                ),
                received_at=BASE + timedelta(seconds=index * 5),
            )
            for index in range(6)
        ]
        pipeline.ingest(records)

    assert event_store.search(EventQuery(tenant="acme")).total == 6
    assert event_store.search(EventQuery(tenant="globex")).total == 6
    acme_alerts = incidents.list_alerts("acme")
    globex_alerts = incidents.list_alerts("globex")
    assert acme_alerts and globex_alerts
    assert {alert.tenant for alert in acme_alerts} == {"acme"}
    assert {alert.tenant for alert in globex_alerts} == {"globex"}


# ------------------------------------------------------------ throughput -----
def test_ten_thousand_events_arrive_without_loss(pipeline: Pipeline, event_store) -> None:
    generator = TelemetryGenerator(tenant="acme", seed=99)
    records = generator.normal_activity(10_000, BASE, spread_seconds=3600)

    accepted = 0
    for start in range(0, len(records), 500):
        result = pipeline.ingest(records[start : start + 500])
        accepted += result.index_result.accepted if result.index_result else 0

    stored = event_store.search(EventQuery(tenant="acme", size=0)).total
    # Every record is accounted for. Some generated records are genuinely
    # identical (same principal, action and second) and collapse by content
    # hash, so "stored + deduplicated" is the invariant, not "stored".
    assert accepted == len(records)
    assert stored + pipeline.engine.stats.events_deduped == len(records)
    assert pipeline.engine.stats.events_processed > 0


def test_correlation_window_expires(pipeline: Pipeline) -> None:
    """Stages spread beyond the timespan must not correlate."""
    generator = TelemetryGenerator(tenant="acme", seed=5)
    records = generator.account_compromise(BASE)
    # Push the last two stages an hour out, well past the 15 minute window.
    stretched = records[:-2] + [
        record.model_copy(
            update={
                "received_at": record.received_at + timedelta(hours=1),
                "payload": {
                    **record.payload,
                    "timestamp": (record.received_at + timedelta(hours=1)).isoformat(),
                },
            }
        )
        for record in records[-2:]
    ]
    result = pipeline.ingest(stretched)
    assert not any(hit.correlation.id == "sf-corr-0003" for hit in result.hits)


def test_pipeline_stats_are_reported(pipeline: Pipeline) -> None:
    pipeline.ingest(sshd_failures(6))
    stats = pipeline.stats
    assert stats["detection"]["events_processed"] == 6
    assert stats["rules"] > 0
    assert stats["correlations"] > 0
    assert "correlation" in stats
