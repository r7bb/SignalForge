"""Incident case management.

Responsibilities:

* persist alerts idempotently (an alert that fires twice becomes one row with
  an occurrence count, which is also what keeps incidents from duplicating);
* open or extend an incident from a correlation hit, or from a single alert
  that is severe enough on its own;
* rebuild the investigation timeline by pivoting on the incident's entities
  (same user, same IP, same host, same session) against the event store;
* enforce the incident state machine and write an audit entry for every
  transition, note, assignment and response action.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..attack import kill_chain, sort_tactics
from ..config import Settings, get_settings
from ..correlate.engine import CorrelationHit
from ..correlate.risk import risk_level, score_incident
from ..models.alert import Alert, AlertStatus
from ..models.incident import (
    ALLOWED_TRANSITIONS,
    Incident,
    IncidentNote,
    IncidentSeverity,
    IncidentStatus,
    TimelineEntry,
)
from ..models.ocsf import OcsfEvent
from ..storage import db as dbm
from ..storage.events import EventStore

log = logging.getLogger("signalforge.incidents")

#: Single alerts at or above this risk open an incident on their own.
SINGLE_ALERT_INCIDENT_THRESHOLD = 70

SEVERITY_FOR_LEVEL = {
    "informational": IncidentSeverity.INFORMATIONAL,
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
}


class IncidentError(Exception):
    """Invalid case-management operation (bad transition, unknown incident)."""


class IncidentManager:
    def __init__(
        self,
        session_factory: Any,
        event_store: Optional[EventStore] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self.session_factory = session_factory
        self.event_store = event_store
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def record_alert(self, alert: Alert) -> Tuple[Alert, bool]:
        """Upsert an alert by ``(tenant, dedup_key)``.  Returns ``(alert, created)``."""
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Alert).where(
                    dbm.Alert.tenant == alert.tenant,
                    dbm.Alert.dedup_key == alert.dedup_key,
                )
            ).first()
            if row is None:
                row = dbm.Alert(id=alert.alert_id)
                _alert_to_row(alert, row)
                session.add(row)
                dbm.record_audit(
                    session,
                    tenant=alert.tenant,
                    actor="detector",
                    action="alert.created",
                    entity_type="alert",
                    entity_id=row.id,
                    detail=alert.rule_title,
                    rule_id=alert.rule_id,
                    risk_score=alert.risk_score,
                )
                session.commit()
                return alert, True

            # Repeat of a known alert: merge rather than duplicate.
            merged = _row_to_alert(row)
            merged.occurrences = row.occurrences + alert.occurrences
            merged.last_seen = max(merged.last_seen, alert.last_seen)
            merged.first_seen = min(merged.first_seen, alert.first_seen)
            for event_id in alert.event_ids:
                if event_id not in merged.event_ids:
                    merged.event_ids.append(event_id)
            if alert.risk_score > merged.risk_score:
                merged.risk_score = alert.risk_score
                merged.risk_level = alert.risk_level
                merged.risk_factors = alert.risk_factors
            merged.detection = alert.detection
            _alert_to_row(merged, row)
            dbm.record_audit(
                session,
                tenant=alert.tenant,
                actor="detector",
                action="alert.repeated",
                entity_type="alert",
                entity_id=row.id,
                occurrences=merged.occurrences,
            )
            session.commit()
            return merged, False

    def list_alerts(
        self,
        tenant: str,
        *,
        status: Optional[Sequence[str]] = None,
        rule_id: Optional[str] = None,
        risk_level: Optional[Sequence[str]] = None,
        min_risk: Optional[int] = None,
        principal: Optional[str] = None,
        source_ip: Optional[str] = None,
        incident_id: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Alert]:
        with self.session_factory() as session:
            query = select(dbm.Alert).where(dbm.Alert.tenant == tenant)
            if status:
                query = query.where(dbm.Alert.status.in_(list(status)))
            if rule_id:
                query = query.where(dbm.Alert.rule_id == rule_id)
            if risk_level:
                query = query.where(dbm.Alert.risk_level.in_(list(risk_level)))
            if min_risk is not None:
                query = query.where(dbm.Alert.risk_score >= min_risk)
            if principal:
                query = query.where(dbm.Alert.principal == principal)
            if source_ip:
                query = query.where(dbm.Alert.source_ip == source_ip)
            if incident_id:
                query = query.where(dbm.Alert.incident_id == incident_id)
            if since:
                query = query.where(dbm.Alert.last_seen >= since)
            query = query.order_by(dbm.Alert.risk_score.desc(), dbm.Alert.last_seen.desc())
            rows = session.scalars(query.limit(limit).offset(offset)).all()
            return [_row_to_alert(row) for row in rows]

    def get_alert(self, tenant: str, alert_id: str) -> Optional[Alert]:
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Alert).where(dbm.Alert.tenant == tenant, dbm.Alert.id == alert_id)
            ).first()
            return _row_to_alert(row) if row else None

    def alert_exists_elsewhere(self, alert_id: str, tenant: str) -> bool:
        """True when the id is real but belongs to a different tenant (-> 403)."""
        with self.session_factory() as session:
            row = session.get(dbm.Alert, alert_id)
            return row is not None and row.tenant != tenant

    def incident_exists_elsewhere(self, reference: str, tenant: str) -> bool:
        with self.session_factory() as session:
            row = session.get(dbm.Incident, reference)
            if row is None:
                row = session.scalars(
                    select(dbm.Incident).where(dbm.Incident.key == reference)
                ).first()
            return row is not None and row.tenant != tenant

    def set_alert_status(
        self,
        tenant: str,
        alert_id: str,
        status: AlertStatus,
        actor: str,
        reason: Optional[str] = None,
    ) -> Alert:
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Alert).where(dbm.Alert.tenant == tenant, dbm.Alert.id == alert_id)
            ).first()
            if row is None:
                raise IncidentError("unknown alert %r" % alert_id)
            previous = row.status
            row.status = status.value
            payload = dict(row.payload or {})
            payload["status"] = status.value
            if reason:
                payload["suppressed_reason"] = reason
            row.payload = payload
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="alert.status_changed",
                entity_type="alert",
                entity_id=alert_id,
                detail=reason,
                from_status=previous,
                to_status=status.value,
            )
            session.commit()
            return _row_to_alert(row)

    def top_rules(self, tenant: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Noisiest rules by alert count - the tuning worklist."""
        with self.session_factory() as session:
            rows = session.scalars(select(dbm.Alert).where(dbm.Alert.tenant == tenant)).all()
        counts: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            entry = counts.setdefault(
                row.rule_id,
                {
                    "rule_id": row.rule_id,
                    "rule_title": row.rule_title,
                    "alerts": 0,
                    "occurrences": 0,
                    "max_risk": 0,
                },
            )
            entry["alerts"] += 1
            entry["occurrences"] += row.occurrences
            entry["max_risk"] = max(entry["max_risk"], row.risk_score)
        return sorted(counts.values(), key=lambda item: item["occurrences"], reverse=True)[:limit]

    def get_alerts(self, tenant: str, alert_ids: Sequence[str]) -> List[Alert]:
        if not alert_ids:
            return []
        with self.session_factory() as session:
            rows = session.scalars(
                select(dbm.Alert).where(
                    dbm.Alert.tenant == tenant, dbm.Alert.id.in_(list(alert_ids))
                )
            ).all()
            return [_row_to_alert(row) for row in rows]

    # ------------------------------------------------------------------ #
    # Incident creation
    # ------------------------------------------------------------------ #
    def open_from_hit(self, hit: CorrelationHit, *, intel_hit: bool = False) -> Incident:
        """Create or extend the incident for a correlation hit."""
        alerts = hit.alerts
        tenant = alerts[0].tenant if alerts else "default"
        assessment = score_incident(alerts, scenario_complete=hit.complete, intel_hit=intel_hit)
        title = hit.correlation.title
        summary = hit.correlation.description or None
        return self._upsert_incident(
            tenant=tenant,
            dedup_key=hit.dedup_key,
            title=title,
            summary=summary,
            scenario=hit.scenario,
            alerts=alerts,
            risk_score=assessment.score,
            risk_factors=assessment.factors,
            tactics=hit.tactics,
            techniques=hit.techniques,
            first_seen=hit.first_seen,
            last_seen=hit.last_seen,
            source="correlator",
            sequence=hit.sequence,
        )

    def open_from_alert(self, alert: Alert, *, force: bool = False) -> Optional[Incident]:
        """Open an incident for a single alert that is severe enough alone."""
        if not force and alert.risk_score < SINGLE_ALERT_INCIDENT_THRESHOLD:
            return None
        dedup_key = hashlib.sha256(
            "|".join(
                [
                    alert.tenant,
                    "single",
                    alert.rule_id,
                    alert.principal or "-",
                    alert.source_ip or "-",
                ]
            ).encode("utf-8")
        ).hexdigest()[:32]
        return self._upsert_incident(
            tenant=alert.tenant,
            dedup_key=dedup_key,
            title=alert.rule_title,
            summary=alert.description,
            scenario=None,
            alerts=[alert],
            risk_score=alert.risk_score,
            risk_factors=alert.risk_factors,
            tactics=alert.tactics,
            techniques=alert.techniques,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            source="detector",
            sequence=[alert.rule_id],
        )

    def _upsert_incident(
        self,
        *,
        tenant: str,
        dedup_key: str,
        title: str,
        summary: Optional[str],
        scenario: Optional[str],
        alerts: Sequence[Alert],
        risk_score: int,
        risk_factors: Sequence[str],
        tactics: Sequence[str],
        techniques: Sequence[str],
        first_seen: datetime,
        last_seen: datetime,
        source: str,
        sequence: Sequence[str],
    ) -> Incident:
        window = timedelta(seconds=self.settings.incident_dedup_window_seconds)
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Incident)
                .where(dbm.Incident.tenant == tenant, dbm.Incident.dedup_key == dedup_key)
                .order_by(dbm.Incident.last_seen.desc())
            ).first()

            reopen = False
            if row is not None:
                existing_last_seen = _as_utc(row.last_seen)
                terminal = row.status in {
                    IncidentStatus.RESOLVED.value,
                    IncidentStatus.CLOSED_FALSE_POSITIVE.value,
                }
                if terminal or last_seen - existing_last_seen > window:
                    # Old or closed: this is a new incident, not an update.
                    row = None
                    reopen = terminal

            if row is None:
                incident = Incident(
                    tenant=tenant,
                    key=dbm.next_incident_key(session, tenant),
                    title=title,
                    summary=summary,
                    scenario=scenario,
                    dedup_key=dedup_key,
                    risk_score=risk_score,
                    risk_factors=list(risk_factors),
                    severity=_severity_for_risk(risk_score),
                    tactics=sort_tactics(tactics),
                    techniques=list(dict.fromkeys(techniques)),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    principal=alerts[0].principal if alerts else None,
                    alert_ids=[alert.alert_id for alert in alerts],
                    event_ids=_merge_event_ids(alerts),
                    entity_keys=_merge_entity_keys(alerts),
                    source_ips=_distinct(alert.source_ip for alert in alerts),
                    hostnames=_distinct(alert.hostname for alert in alerts),
                )
                incident.record(
                    "incident.created",
                    actor=source,
                    detail="%s (%s)" % (title, ", ".join(sequence) or "single alert"),
                    risk_score=risk_score,
                    scenario=scenario,
                    reopened=reopen,
                )
                new_row = dbm.Incident(id=incident.incident_id)
                _incident_to_row(incident, new_row)
                session.add(new_row)
                # Link against the *persisted* alert rows: a repeat alert was
                # merged into an existing row, so its in-memory id is not the
                # one the API will look up.
                incident.alert_ids = self._link_alerts(session, incident, alerts)
                _incident_to_row(incident, new_row)
                dbm.record_audit(
                    session,
                    tenant=tenant,
                    actor=source,
                    action="incident.created",
                    entity_type="incident",
                    entity_id=incident.incident_id,
                    detail=incident.key,
                    risk_score=risk_score,
                    scenario=scenario,
                )
                session.commit()
                log.info(
                    "incident opened",
                    extra={"key": incident.key, "risk": risk_score, "tenant": tenant},
                )
                return incident

            incident = _row_to_incident(row)
            before = incident.risk_score
            incident.alert_ids = _distinct(
                incident.alert_ids + self._link_alerts(session, incident, alerts)
            )
            incident.event_ids = _distinct(incident.event_ids + _merge_event_ids(alerts))
            incident.entity_keys = _distinct(incident.entity_keys + _merge_entity_keys(alerts))
            incident.source_ips = _distinct(
                incident.source_ips + [a.source_ip for a in alerts if a.source_ip]
            )
            incident.hostnames = _distinct(
                incident.hostnames + [a.hostname for a in alerts if a.hostname]
            )
            incident.tactics = sort_tactics(list(incident.tactics) + list(tactics))
            incident.techniques = _distinct(list(incident.techniques) + list(techniques))
            incident.last_seen = max(incident.last_seen, last_seen)
            incident.first_seen = min(incident.first_seen, first_seen)
            if risk_score > incident.risk_score:
                incident.risk_score = risk_score
                incident.risk_factors = list(risk_factors)
                incident.severity = _severity_for_risk(risk_score)
            incident.record(
                "incident.updated",
                actor=source,
                detail="risk %d -> %d" % (before, incident.risk_score),
                alerts=len(incident.alert_ids),
            )
            _incident_to_row(incident, row)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=source,
                action="incident.updated",
                entity_type="incident",
                entity_id=incident.incident_id,
                detail=incident.key,
                risk_score=incident.risk_score,
            )
            session.commit()
            return incident

    def _link_alerts(
        self, session: Session, incident: Incident, alerts: Sequence[Alert]
    ) -> List[str]:
        """Attach alerts to an incident.  Returns the persisted alert row ids.

        An alert may already belong to a single-alert incident opened before the
        chain completed.  Those get superseded, so one intrusion is one case
        rather than one case per stage.
        """
        linked: List[str] = []
        previous_incidents: List[str] = []
        for alert in alerts:
            row = session.scalars(
                select(dbm.Alert).where(
                    dbm.Alert.tenant == alert.tenant,
                    dbm.Alert.dedup_key == alert.dedup_key,
                )
            ).first()
            if row is None:
                row = dbm.Alert(id=alert.alert_id)
                _alert_to_row(alert, row)
                session.add(row)
                session.flush()
            if row.incident_id and row.incident_id != incident.incident_id:
                previous_incidents.append(row.incident_id)
            row.incident_id = incident.incident_id
            if row.status == AlertStatus.NEW.value:
                row.status = AlertStatus.CORRELATED.value
            payload = dict(row.payload or {})
            payload["incident_id"] = incident.incident_id
            payload["status"] = row.status
            payload["alert_id"] = row.id
            row.payload = payload
            if row.id not in linked:
                linked.append(row.id)

        session.flush()
        self._supersede(session, incident, previous_incidents)
        return linked

    @staticmethod
    def _supersede(session: Session, incident: Incident, candidates: Sequence[str]) -> List[str]:
        """Close incidents whose every alert now belongs to ``incident``."""
        superseded: List[str] = []
        for candidate_id in dict.fromkeys(candidates):
            if candidate_id == incident.incident_id:
                continue
            row = session.get(dbm.Incident, candidate_id)
            if row is None or row.status in {
                IncidentStatus.RESOLVED.value,
                IncidentStatus.CLOSED_FALSE_POSITIVE.value,
            }:
                continue
            remaining = session.scalars(
                select(dbm.Alert).where(dbm.Alert.incident_id == candidate_id)
            ).all()
            if remaining:
                # It still owns evidence of its own, so it stands alone.
                continue
            row.status = IncidentStatus.RESOLVED.value
            row.closed_at = datetime.now(tz=timezone.utc)
            row.close_reason = "Superseded by %s" % incident.key
            payload = dict(row.payload or {})
            payload["status"] = row.status
            payload["close_reason"] = row.close_reason
            payload["superseded_by"] = incident.key
            row.payload = payload
            dbm.record_audit(
                session,
                tenant=row.tenant,
                actor="correlator",
                action="incident.superseded",
                entity_type="incident",
                entity_id=candidate_id,
                detail=row.close_reason,
                superseded_by=incident.incident_id,
            )
            superseded.append(candidate_id)
            log.info("incident superseded", extra={"incident": row.key, "by": incident.key})
        return superseded

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def get(self, tenant: str, reference: str) -> Optional[Incident]:
        with self.session_factory() as session:
            row = self._find(session, tenant, reference)
            return _row_to_incident(row) if row else None

    def list(
        self,
        tenant: str,
        *,
        status: Optional[Sequence[str]] = None,
        severity: Optional[Sequence[str]] = None,
        owner: Optional[str] = None,
        scenario: Optional[str] = None,
        min_risk: Optional[int] = None,
        open_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Incident]:
        with self.session_factory() as session:
            query = select(dbm.Incident).where(dbm.Incident.tenant == tenant)
            if status:
                query = query.where(dbm.Incident.status.in_(list(status)))
            if open_only:
                query = query.where(
                    dbm.Incident.status.notin_(
                        [
                            IncidentStatus.RESOLVED.value,
                            IncidentStatus.CLOSED_FALSE_POSITIVE.value,
                        ]
                    )
                )
            if severity:
                query = query.where(dbm.Incident.severity.in_(list(severity)))
            if owner:
                query = query.where(dbm.Incident.owner == owner)
            if scenario:
                query = query.where(dbm.Incident.scenario == scenario)
            if min_risk is not None:
                query = query.where(dbm.Incident.risk_score >= min_risk)
            query = query.order_by(dbm.Incident.risk_score.desc(), dbm.Incident.last_seen.desc())
            rows = session.scalars(query.limit(limit).offset(offset)).all()
            return [_row_to_incident(row) for row in rows]

    def counts(self, tenant: str) -> Dict[str, Any]:
        with self.session_factory() as session:
            incidents = session.scalars(
                select(dbm.Incident).where(dbm.Incident.tenant == tenant)
            ).all()
            alerts = session.scalars(select(dbm.Alert).where(dbm.Alert.tenant == tenant)).all()
        open_statuses = {s.value for s in IncidentStatus} - {
            IncidentStatus.RESOLVED.value,
            IncidentStatus.CLOSED_FALSE_POSITIVE.value,
        }
        by_status: Dict[str, int] = {}
        for incident in incidents:
            by_status[incident.status] = by_status.get(incident.status, 0) + 1
        return {
            "incidents_total": len(incidents),
            "incidents_open": sum(1 for i in incidents if i.status in open_statuses),
            "incidents_by_status": by_status,
            "alerts_total": len(alerts),
            "alerts_critical": sum(1 for a in alerts if a.risk_level == "critical"),
            "alerts_high": sum(1 for a in alerts if a.risk_level == "high"),
        }

    # ------------------------------------------------------------------ #
    # Analyst workflow
    # ------------------------------------------------------------------ #
    def transition(
        self,
        tenant: str,
        reference: str,
        target: IncidentStatus,
        actor: str,
        reason: Optional[str] = None,
    ) -> Incident:
        with self.session_factory() as session:
            row = self._require(session, tenant, reference)
            incident = _row_to_incident(row)
            if incident.status == target:
                return incident
            if target not in ALLOWED_TRANSITIONS.get(incident.status, set()):
                raise IncidentError(
                    "cannot move %s from %s to %s"
                    % (incident.key, incident.status.value, target.value)
                )
            previous = incident.status
            incident.status = target
            if target in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED_FALSE_POSITIVE}:
                incident.closed_at = datetime.now(tz=timezone.utc)
                incident.close_reason = reason
            else:
                incident.closed_at = None
            incident.timeline.append(
                TimelineEntry(
                    time=datetime.now(tz=timezone.utc),
                    kind="status",
                    title="%s -> %s" % (previous.value, target.value),
                    detail=reason,
                    actor=actor,
                )
            )
            incident.record(
                "incident.status_changed",
                actor=actor,
                detail=reason,
                from_status=previous.value,
                to_status=target.value,
            )
            _incident_to_row(incident, row)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="incident.status_changed",
                entity_type="incident",
                entity_id=incident.incident_id,
                detail=reason,
                from_status=previous.value,
                to_status=target.value,
            )
            session.commit()
            return incident

    def assign(self, tenant: str, reference: str, owner: Optional[str], actor: str) -> Incident:
        with self.session_factory() as session:
            row = self._require(session, tenant, reference)
            incident = _row_to_incident(row)
            previous = incident.owner
            incident.owner = owner
            incident.record(
                "incident.assigned",
                actor=actor,
                detail="%s -> %s" % (previous or "unassigned", owner or "unassigned"),
            )
            _incident_to_row(incident, row)
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=actor,
                action="incident.assigned",
                entity_type="incident",
                entity_id=incident.incident_id,
                detail=owner,
                previous_owner=previous,
            )
            session.commit()
            return incident

    def add_note(self, tenant: str, reference: str, author: str, body: str) -> Incident:
        if not body.strip():
            raise IncidentError("note body cannot be empty")
        with self.session_factory() as session:
            row = self._require(session, tenant, reference)
            incident = _row_to_incident(row)
            note = IncidentNote(author=author, body=body)
            incident.notes.append(note)
            incident.timeline.append(
                TimelineEntry(
                    time=note.time,
                    kind="note",
                    title="Analyst note",
                    detail=body,
                    actor=author,
                )
            )
            incident.record("incident.note_added", actor=author, detail=body[:200])
            _incident_to_row(incident, row)
            session.add(
                dbm.IncidentNote(
                    id=note.id,
                    incident_id=incident.incident_id,
                    author=author,
                    body=body,
                )
            )
            dbm.record_audit(
                session,
                tenant=tenant,
                actor=author,
                action="incident.note_added",
                entity_type="incident",
                entity_id=incident.incident_id,
                detail=body[:200],
            )
            session.commit()
            return incident

    def append_timeline(
        self, tenant: str, reference: str, entry: TimelineEntry, actor: str = "system"
    ) -> Incident:
        with self.session_factory() as session:
            row = self._require(session, tenant, reference)
            incident = _row_to_incident(row)
            incident.timeline.append(entry)
            incident.record("incident.timeline_appended", actor=actor, detail=entry.title)
            _incident_to_row(incident, row)
            session.commit()
            return incident

    def audit_trail(
        self, tenant: str, reference: Optional[str] = None, limit: int = 200
    ) -> List[Dict[str, Any]]:
        with self.session_factory() as session:
            query = select(dbm.AuditLog).where(dbm.AuditLog.tenant == tenant)
            if reference:
                row = self._find(session, tenant, reference)
                if row is not None:
                    # An incident's history includes what was done *about* it:
                    # response actions are audited under their own entity id, so
                    # pull those in rather than showing only incident rows.
                    entity_ids = [row.id]
                    entity_ids.extend(
                        action.id
                        for action in session.scalars(
                            select(dbm.ResponseAction).where(
                                dbm.ResponseAction.incident_id == row.id
                            )
                        ).all()
                    )
                    entity_ids.extend(
                        alert.id
                        for alert in session.scalars(
                            select(dbm.Alert).where(dbm.Alert.incident_id == row.id)
                        ).all()
                    )
                    query = query.where(dbm.AuditLog.entity_id.in_(entity_ids))
            rows = session.scalars(
                query.order_by(dbm.AuditLog.created_at.desc()).limit(limit)
            ).all()
            return [
                {
                    "id": row.id,
                    "time": row.created_at,
                    "actor": row.actor,
                    "action": row.action,
                    "entity_type": row.entity_type,
                    "entity_id": row.entity_id,
                    "detail": row.detail,
                    "data": row.data,
                }
                for row in rows
            ]

    # ------------------------------------------------------------------ #
    # Investigation timeline
    # ------------------------------------------------------------------ #
    def build_timeline(
        self,
        tenant: str,
        reference: str,
        *,
        pad_seconds: int = 900,
        size: int = 300,
    ) -> List[TimelineEntry]:
        """Pivot on the incident's entities to reconstruct what happened."""
        incident = self.get(tenant, reference)
        if incident is None:
            raise IncidentError("unknown incident %r" % reference)

        entries: List[TimelineEntry] = []
        alerts = self.get_alerts(tenant, incident.alert_ids)
        for alert in alerts:
            entries.append(
                TimelineEntry(
                    time=alert.first_seen,
                    kind="alert",
                    title=alert.rule_title,
                    detail="risk %d/100 (%s), %d event(s)"
                    % (alert.risk_score, alert.risk_level, alert.detection.event_count),
                    actor=alert.principal,
                    source_ip=alert.source_ip,
                    hostname=alert.hostname,
                    alert_id=alert.alert_id,
                    severity=alert.risk_level,
                    tactics=alert.tactics,
                )
            )

        if self.event_store is not None:
            principals = _distinct(
                [incident.principal]
                + [a.principal for a in alerts]
                + [a.target_principal for a in alerts]
            )
            events = self.event_store.timeline(
                tenant,
                principals=principals,
                source_ips=incident.source_ips,
                hostnames=incident.hostnames,
                session_uids=_distinct(a.session_uid for a in alerts),
                start=incident.first_seen - timedelta(seconds=pad_seconds),
                end=incident.last_seen + timedelta(seconds=pad_seconds),
                size=size,
            )
            for event in events:
                entries.append(_event_to_timeline(event))

        entries.extend(incident.timeline)
        # Event time is authoritative: late-arriving logs land in the right slot.
        entries.sort(key=lambda entry: entry.time)
        return entries[:size]

    def attack_path(self, tenant: str, reference: str) -> List[Dict[str, str]]:
        """The ATT&CK kill chain shown on the incident screen."""
        incident = self.get(tenant, reference)
        if incident is None:
            raise IncidentError("unknown incident %r" % reference)
        return kill_chain(incident.tactics)

    # ------------------------------------------------------------------ #
    # Row lookup
    # ------------------------------------------------------------------ #
    @staticmethod
    def _find(session: Session, tenant: str, reference: str) -> Optional[dbm.Incident]:
        """Look an incident up by uuid or by its human key (``INC-2041``)."""
        row = session.scalars(
            select(dbm.Incident).where(dbm.Incident.tenant == tenant, dbm.Incident.id == reference)
        ).first()
        if row is not None:
            return row
        return session.scalars(
            select(dbm.Incident).where(dbm.Incident.tenant == tenant, dbm.Incident.key == reference)
        ).first()

    def _require(self, session: Session, tenant: str, reference: str) -> dbm.Incident:
        row = self._find(session, tenant, reference)
        if row is None:
            raise IncidentError("unknown incident %r for tenant %r" % (reference, tenant))
        return row


# --------------------------------------------------------------------------- #
# Row <-> model conversion
# --------------------------------------------------------------------------- #
def _alert_to_row(alert: Alert, row: dbm.Alert) -> dbm.Alert:
    row.tenant = alert.tenant
    row.rule_id = alert.rule_id
    row.rule_title = alert.rule_title
    row.rule_level = alert.rule_level
    row.status = alert.status.value if isinstance(alert.status, AlertStatus) else str(alert.status)
    row.risk_score = alert.risk_score
    row.risk_level = alert.risk_level
    row.severity = alert.severity
    row.confidence = alert.confidence
    row.principal = alert.principal
    row.target_principal = alert.target_principal
    row.source_ip = alert.source_ip
    row.hostname = alert.hostname
    row.session_uid = alert.session_uid
    row.dedup_key = alert.dedup_key
    row.occurrences = alert.occurrences
    row.first_seen = alert.first_seen
    row.last_seen = alert.last_seen
    row.tactics = list(alert.tactics)
    row.techniques = list(alert.techniques)
    row.incident_id = alert.incident_id or row.incident_id
    row.payload = alert.model_dump(mode="json")
    return row


def _row_to_alert(row: dbm.Alert) -> Alert:
    payload = dict(row.payload or {})
    if payload:
        payload.setdefault("alert_id", row.id)
        return Alert.model_validate(payload)
    return Alert(
        alert_id=row.id,
        tenant=row.tenant,
        rule_id=row.rule_id,
        rule_title=row.rule_title,
        rule_level=row.rule_level,
        risk_score=row.risk_score,
        risk_level=row.risk_level,
        principal=row.principal,
        source_ip=row.source_ip,
        hostname=row.hostname,
        dedup_key=row.dedup_key,
        occurrences=row.occurrences,
        first_seen=_as_utc(row.first_seen),
        last_seen=_as_utc(row.last_seen),
        tactics=list(row.tactics or []),
        techniques=list(row.techniques or []),
    )


def _incident_to_row(incident: Incident, row: dbm.Incident) -> dbm.Incident:
    row.tenant = incident.tenant
    row.key = incident.key
    row.title = incident.title
    row.summary = incident.summary
    row.status = incident.status.value
    row.severity = incident.severity.value
    row.owner = incident.owner
    row.risk_score = incident.risk_score
    row.scenario = incident.scenario
    row.dedup_key = incident.dedup_key
    row.principal = incident.principal
    row.first_seen = incident.first_seen
    row.last_seen = incident.last_seen
    row.closed_at = incident.closed_at
    row.close_reason = incident.close_reason
    row.tactics = list(incident.tactics)
    row.techniques = list(incident.techniques)
    row.payload = incident.model_dump(mode="json")
    return row


def _row_to_incident(row: dbm.Incident) -> Incident:
    payload = dict(row.payload or {})
    if payload:
        payload.setdefault("incident_id", row.id)
        # Columns are authoritative for anything an analyst can change.
        payload["status"] = row.status
        payload["owner"] = row.owner
        payload["severity"] = row.severity
        payload["risk_score"] = row.risk_score
        payload["key"] = row.key
        return Incident.model_validate(payload)
    return Incident(
        incident_id=row.id,
        tenant=row.tenant,
        key=row.key,
        title=row.title,
        status=IncidentStatus(row.status),
        severity=IncidentSeverity(row.severity),
        owner=row.owner,
        risk_score=row.risk_score,
        scenario=row.scenario,
        dedup_key=row.dedup_key,
        principal=row.principal,
        first_seen=_as_utc(row.first_seen),
        last_seen=_as_utc(row.last_seen),
        tactics=list(row.tactics or []),
        techniques=list(row.techniques or []),
    )


def _event_to_timeline(event: OcsfEvent) -> TimelineEntry:
    return TimelineEntry(
        time=event.time,
        kind="event",
        title=event.type_name or event.class_name or "Event",
        detail=event.message,
        actor=event.principal,
        source_ip=event.source_ip,
        hostname=event.hostname,
        event_id=event.sf_event_id,
        class_name=event.class_name,
        outcome=event.status,
        severity=event.severity,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _severity_for_risk(risk_score: int) -> IncidentSeverity:
    return SEVERITY_FOR_LEVEL[risk_level(risk_score)]


def _merge_event_ids(alerts: Sequence[Alert]) -> List[str]:
    out: List[str] = []
    for alert in alerts:
        for event_id in alert.event_ids:
            if event_id not in out:
                out.append(event_id)
    return out


def _merge_entity_keys(alerts: Sequence[Alert]) -> List[str]:
    out: List[str] = []
    for alert in alerts:
        for key in alert.entity_keys():
            if key not in out:
                out.append(key)
    return out


def _distinct(values: Optional[Iterable[str]]) -> Optional[List[str]]:
    out: List[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
