"""Celery worker: scheduled maintenance and out-of-band jobs.

Nothing on the detection path lives here - this is housekeeping:

* retry events spooled while the event store was unreachable;
* expire sliding-window state and log engine counters;
* re-match SBOM inventories against known advisories;
* age out resolved incidents' window state and prune the intel cache;
* run a retro-hunt on demand when an analyst asks for one from the UI.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from signalforge.config import get_settings
from signalforge.enrich import ThreatIntelService
from signalforge.incidents import IncidentError, IncidentManager
from signalforge.logging_setup import configure_logging
from signalforge.models.incident import IncidentStatus
from signalforge.sbom import SbomService
from signalforge.sigma import compile_rule, load_ruleset
from signalforge.storage import db as dbm
from signalforge.storage.events import get_event_store
from signalforge.telemetry import SPOOLED_EVENTS

log = logging.getLogger("signalforge.worker")

settings = get_settings()
configure_logging(settings.log_level, service="worker")

try:
    from celery import Celery
    from celery.schedules import crontab

    CELERY_AVAILABLE = True
except ImportError:  # pragma: no cover - celery is an optional extra
    CELERY_AVAILABLE = False
    Celery = None  # type: ignore[assignment,misc]


def _broker_url() -> str:
    return settings.celery_broker_url or settings.redis_url or "memory://"


if CELERY_AVAILABLE:
    app = Celery(
        "signalforge",
        broker=_broker_url(),
        backend=settings.celery_result_backend or settings.redis_url or "cache+memory://",
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_default_retry_delay=10,
        task_time_limit=600,
        beat_schedule={
            "flush-event-spool": {
                "task": "signalforge.flush_spool",
                "schedule": 60.0,
            },
            "sweep-detection-state": {
                "task": "signalforge.sweep_state",
                "schedule": 300.0,
            },
            "rematch-supply-chain": {
                "task": "signalforge.rematch_vulnerabilities",
                "schedule": crontab(minute=0, hour="*/6"),
            },
            "prune-indicator-cache": {
                "task": "signalforge.prune_indicators",
                "schedule": crontab(minute=30, hour=3),
            },
            # Every two minutes: a 15-minute acknowledge target is not much use
            # if the breach is noticed an hour late.
            "sweep-sla-breaches": {
                "task": "signalforge.sweep_sla",
                "schedule": 120.0,
            },
            "wake-parked-incidents": {
                "task": "signalforge.wake_parked_incidents",
                "schedule": 300.0,
            },
        },
    )
else:  # pragma: no cover

    class _Stub:
        """Lets the module import (and the functions be called directly) without celery."""

        def task(self, *args: Any, **kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                return func

            return decorator

    app = _Stub()  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
@app.task(name="signalforge.flush_spool", bind=False)
def flush_spool() -> Dict[str, Any]:
    """Re-send events parked on disk while the event store was down."""
    store = get_event_store(settings)
    result = store.flush_spool()
    spooled = getattr(store, "spooled_count", 0)
    SPOOLED_EVENTS.set(spooled)
    if result.indexed or result.spooled:
        log.info("spool flush", extra={"indexed": result.indexed, "still_spooled": result.spooled})
    return {
        "indexed": result.indexed,
        "duplicates": result.duplicates,
        "still_spooled": result.spooled,
    }


@app.task(name="signalforge.sweep_state", bind=False)
def sweep_state() -> Dict[str, Any]:
    """Placeholder sweep for deployments that run detection in-process.

    The streaming detector sweeps its own windows on its maintenance tick; this
    task exists so a single-process deployment still expires state.
    """
    ruleset = load_ruleset(settings.detections_path)
    return {"rules": len(ruleset.rules), "correlations": len(ruleset.correlations)}


@app.task(name="signalforge.sweep_sla", bind=False)
def sweep_sla(tenant: Optional[str] = None) -> Dict[str, Any]:
    """Escalate incidents that have blown an SLA clock.

    Escalation is idempotent (``sla_escalated_at``), so running this on a tight
    schedule re-pages nobody: the first pass records the breach and bumps the
    severity, later passes find nothing to do.
    """
    dbm.init_db(settings)
    manager = IncidentManager(dbm.get_session_factory(settings), settings=settings)
    if not settings.sla_escalation_enabled:
        breaches = manager.sla_breaches(tenant)
        log.info("SLA sweep (escalation disabled)", extra={"breaches": len(breaches)})
        return {"breaches": len(breaches), "escalated": 0, "escalation_enabled": False}

    escalated = []
    for incident in manager.sla_breaches(tenant):
        if manager.escalate_sla_breach(incident.tenant, incident.key) is not None:
            escalated.append(incident.key)
    log.info("SLA sweep", extra={"escalated": len(escalated)})
    return {"escalated": len(escalated), "incidents": escalated, "escalation_enabled": True}


@app.task(name="signalforge.wake_parked_incidents", bind=False)
def wake_parked_incidents(tenant: Optional[str] = None) -> Dict[str, Any]:
    """Return parked incidents to the queue once their timer expires.

    A ``waiting`` incident with an elapsed wake-up time is work that has become
    actionable again and nobody has been told.
    """
    dbm.init_db(settings)
    manager = IncidentManager(dbm.get_session_factory(settings), settings=settings)
    woken = []
    for incident in manager.due_for_wake_up(tenant):
        try:
            manager.transition(
                incident.tenant,
                incident.key,
                IncidentStatus.INVESTIGATING,
                actor="sla-monitor",
                reason="wake-up timer expired (%s)"
                % (incident.waiting_reason or "no reason given"),
            )
            woken.append(incident.key)
        except IncidentError as exc:  # pragma: no cover - defensive
            log.warning(
                "could not wake incident", extra={"incident": incident.key, "error": str(exc)}
            )
    log.info("woke parked incidents", extra={"count": len(woken)})
    return {"woken": len(woken), "incidents": woken}


@app.task(name="signalforge.rematch_vulnerabilities", bind=False)
def rematch_vulnerabilities(tenant: Optional[str] = None) -> Dict[str, Any]:
    """Re-run every advisory against every ingested SBOM."""
    dbm.init_db(settings)
    service = SbomService(dbm.get_session_factory(settings))
    matched = service.rematch(tenant=tenant)
    log.info("supply-chain rematch", extra={"matches": len(matched)})
    return {"matches": len(matched)}


@app.task(name="signalforge.prune_indicators", bind=False)
def prune_indicators(max_age_days: int = 30) -> Dict[str, Any]:
    """Drop cached indicator rows that have not been seen for a while."""
    dbm.init_db(settings)
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=max_age_days)
    factory = dbm.get_session_factory(settings)
    removed = 0
    with factory() as session:
        from sqlalchemy import select

        rows = session.scalars(select(dbm.Indicator)).all()
        for row in rows:
            reference = row.expires_at or row.updated_at
            if reference and reference.replace(tzinfo=timezone.utc) < cutoff:
                session.delete(row)
                removed += 1
        session.commit()
    return {"removed": removed}


@app.task(name="signalforge.retro_hunt", bind=False)
def retro_hunt(rule_id: str, tenant: str, earliest: str = "now-30d") -> Dict[str, Any]:
    """Run one detection over historical events (kicked off from the UI)."""
    ruleset = load_ruleset(settings.detections_path)
    rule = ruleset.rules.get(rule_id)
    if rule is None:
        return {"rule_id": rule_id, "error": "unknown detection"}
    body = compile_rule(rule, tenant=tenant, earliest=earliest, size=200)
    response = get_event_store(settings).raw_search(body)
    hits = response.get("hits", {})
    total = hits.get("total", {})
    return {
        "rule_id": rule_id,
        "total": total.get("value", 0) if isinstance(total, dict) else int(total or 0),
        "groups": response.get("aggregations", {}).get("grouped", {}).get("buckets", []),
    }


@app.task(name="signalforge.enrich_indicator", bind=False)
def enrich_indicator(value: str, type_: str = "ip") -> Dict[str, Any]:
    """Warm the intel cache for an indicator."""
    return ThreatIntelService(settings).lookup(value, type_).to_dict()
