"""Turn a ``*.tests.yml`` case into events and run it through the pipeline.

The YAML event spec is deliberately small:

.. code-block:: yaml

    events:
      - source: linux.sshd            # which mapper handles it
        repeat: 6                     # emit it six times
        interval_seconds: 10          # ten seconds apart
        at: 120                       # starting two minutes after t0
        raw: "{time} web-01 sshd[{i}]: Failed password for alex from 10.0.4.82 ..."
      - source: app.audit
        at: 180
        payload: {action: role_change, user: alex@example.com, new_role: admin}

``{time}`` is substituted with an RFC3164 syslog stamp and ``{i}`` with the
repeat index; structured payloads get the timestamp field their source uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from signalforge.correlate import CorrelationEngine, CorrelationHit, score_incident
from signalforge.detect import DetectionEngine
from signalforge.models.alert import Alert
from signalforge.models.ocsf import OcsfEvent, RawLogRecord
from signalforge.normalize import registry
from signalforge.sigma.loader import iter_rule_files, load_documents, test_file_for

#: Timestamp key each source family carries.
TIMESTAMP_FIELDS: Dict[str, str] = {
    "aws": "eventTime",
    "okta": "published",
    "app": "timestamp",
    "linux": "timestamp",
}

VALID_KINDS = ("positive", "negative", "false_positive")
DEFAULT_EXPECT = {"positive": "alert", "negative": "no_alert", "false_positive": "no_alert"}


@dataclass
class DetectionCase:
    rule_id: str
    rule_path: Path
    test_path: Path
    name: str
    kind: str
    expect: str
    events: List[Dict[str, Any]]
    tenant: str = "acme"
    expect_min_risk: Optional[int] = None
    expect_rule_id: Optional[str] = None

    @property
    def id(self) -> str:
        return "%s::%s::%s" % (self.rule_id, self.kind, self.name.replace(" ", "-"))

    @property
    def target_rule_id(self) -> str:
        return self.expect_rule_id or self.rule_id


@dataclass
class Outcome:
    events: List[OcsfEvent] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    hits: List[CorrelationHit] = field(default_factory=list)

    def alerts_for(self, rule_id: str) -> List[Alert]:
        return [alert for alert in self.alerts if alert.rule_id == rule_id]

    def hits_for(self, correlation_id: str) -> List[CorrelationHit]:
        return [hit for hit in self.hits if hit.correlation.id == correlation_id]

    def max_alert_risk(self, rule_id: str) -> int:
        scores = [alert.risk_score for alert in self.alerts_for(rule_id)]
        return max(scores) if scores else 0

    def max_incident_risk(self, correlation_id: str) -> int:
        scores = [
            score_incident(hit.alerts, scenario_complete=True).score
            for hit in self.hits_for(correlation_id)
        ]
        return max(scores) if scores else 0


def collect_cases(detections_dir: Path) -> List[DetectionCase]:
    """Every test case declared next to a rule in ``detections_dir``."""
    cases: List[DetectionCase] = []
    for rule_path in iter_rule_files(detections_dir):
        test_path = test_file_for(rule_path)
        if test_path is None:
            continue
        documents = load_documents(test_path)
        for document in documents:
            declared_rule = document.get("rule")
            for raw_case in document.get("tests") or []:
                kind = str(raw_case.get("kind") or "positive").lower()
                if kind not in VALID_KINDS:
                    raise ValueError(
                        "%s: unknown test kind %r (expected %s)"
                        % (test_path, kind, ", ".join(VALID_KINDS))
                    )
                cases.append(
                    DetectionCase(
                        rule_id=str(declared_rule or raw_case.get("rule") or ""),
                        rule_path=Path(rule_path),
                        test_path=Path(test_path),
                        name=str(raw_case.get("name") or "unnamed"),
                        kind=kind,
                        expect=str(raw_case.get("expect") or DEFAULT_EXPECT[kind]),
                        events=list(raw_case.get("events") or raw_case.get("logs") or []),
                        tenant=str(raw_case.get("tenant") or "acme"),
                        expect_min_risk=raw_case.get("expect_min_risk"),
                        expect_rule_id=raw_case.get("expect_rule_id"),
                    )
                )
    return cases


def build_records(
    specs: List[Dict[str, Any]], base_time: datetime, tenant: str = "acme"
) -> List[RawLogRecord]:
    """Expand the event specs into raw log records, ordered by event time."""
    records: List[Tuple[datetime, RawLogRecord]] = []
    for spec in specs:
        source = str(spec.get("source") or "app.audit")
        offset = float(spec.get("at", 0))
        repeat = int(spec.get("repeat", 1))
        interval = float(spec.get("interval_seconds", 0))
        for index in range(repeat):
            moment = base_time + timedelta(seconds=offset + index * interval)
            raw = spec.get("raw")
            payload: Dict[str, Any] = dict(spec.get("payload") or {})
            if raw is not None:
                raw = str(raw).format(time=_syslog_stamp(moment), i=index)
            else:
                key = TIMESTAMP_FIELDS.get(source.split(".", 1)[0], "timestamp")
                payload.setdefault(key, moment.isoformat().replace("+00:00", "Z"))
            records.append(
                (
                    moment,
                    RawLogRecord(
                        source=source,
                        tenant=str(spec.get("tenant") or tenant),
                        payload=payload,
                        raw=raw,
                        received_at=moment,
                        collector="detection-test",
                    ),
                )
            )
    records.sort(key=lambda pair: pair[0])
    return [record for _, record in records]


def run_case(
    case: DetectionCase,
    base_time: datetime,
    *,
    engine: DetectionEngine,
    correlator: CorrelationEngine,
) -> Outcome:
    """Normalize -> detect -> correlate, exactly as the services do."""
    outcome = Outcome()
    for record in build_records(case.events, base_time, case.tenant):
        event = registry.normalize(record)
        outcome.events.append(event)
        alerts = engine.process(event)
        outcome.alerts.extend(alerts)
        for alert in alerts:
            outcome.hits.extend(correlator.process(alert))
    return outcome


def _syslog_stamp(moment: datetime) -> str:
    # RFC3164 uses a space-padded day of month: "Sep  9" / "Sep 10".
    return "%s %2d %s" % (moment.strftime("%b"), moment.day, moment.strftime("%H:%M:%S"))
