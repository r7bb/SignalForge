"""Dashboard aggregates."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from signalforge.attack import TACTIC_ORDER, tactic_name
from signalforge.auth import Principal
from signalforge.correlate.risk import RISK_BANDS

from ..deps import current_principal, get_state, tenant_scope
from ..schemas import OverviewResponse
from ..state import AppState

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/overview", response_model=OverviewResponse)
async def overview(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """The numbers on the security-overview panel."""
    now = datetime.now(tz=timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    event_stats = state.event_store.stats(tenant, since=midnight)
    counts = state.incidents.counts(tenant)
    detection_stats = state.pipeline.engine.stats

    return {
        "critical_alerts": counts["alerts_critical"],
        "high_alerts": counts["alerts_high"],
        "events_today": event_stats.get("total", 0),
        "open_incidents": counts["incidents_open"],
        "alerts_total": counts["alerts_total"],
        "incidents_total": counts["incidents_total"],
        "mean_detection_latency_ms": round(detection_stats.mean_latency_ms, 3),
        "events_by_class": event_stats.get("by_class", {}),
        "events_by_severity": event_stats.get("by_severity", {}),
        "incidents_by_status": counts["incidents_by_status"],
        "top_rules": state.incidents.top_rules(tenant, limit=5),
        "supply_chain": state.sbom.stats(tenant),
        "generated_at": now,
    }


@router.get("/mitre")
async def mitre_coverage(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Rule coverage and observed activity per ATT&CK tactic."""
    rules = list(state.ruleset.rules.values()) + list(state.ruleset.correlations.values())
    coverage: Dict[str, Dict[str, Any]] = {
        slug: {
            "tactic": slug,
            "name": tactic_name(slug),
            "rules": 0,
            "techniques": set(),
            "incidents": 0,
        }
        for slug in TACTIC_ORDER
    }
    for rule in rules:
        for tactic in rule.tactics:
            entry = coverage.setdefault(
                tactic,
                {
                    "tactic": tactic,
                    "name": tactic_name(tactic),
                    "rules": 0,
                    "techniques": set(),
                    "incidents": 0,
                },
            )
            entry["rules"] += 1
            entry["techniques"].update(rule.techniques)

    for incident in state.incidents.list(tenant, limit=200):
        for tactic in incident.tactics:
            if tactic in coverage:
                coverage[tactic]["incidents"] += 1

    return {
        "tactics": [
            {
                **entry,
                "techniques": sorted(entry["techniques"]),
                "technique_count": len(entry["techniques"]),
            }
            for entry in coverage.values()
        ]
    }


@router.get("/risk-bands")
async def risk_bands(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    """The documented scoring bands, so the UI and README cannot disagree."""
    bands: List[Dict[str, Any]] = []
    previous_floor = 101
    for floor, name in RISK_BANDS:
        bands.append({"name": name, "min": floor, "max": previous_floor - 1})
        previous_floor = floor
    return {
        "bands": list(reversed(bands)),
        "note": "SignalForge's own experimental model, not an industry standard",
    }


@router.get("/detections")
async def detection_stats(
    hours: int = Query(default=24, ge=1, le=8760),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    since = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    alerts = state.incidents.list_alerts(tenant, since=since, limit=500)
    by_level: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    for alert in alerts:
        by_level[alert.risk_level] = by_level.get(alert.risk_level, 0) + 1
        by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1
    return {
        "window_hours": hours,
        "alerts": len(alerts),
        "by_risk_level": by_level,
        "by_rule": by_rule,
        "engine": state.pipeline.engine.stats.to_dict(),
        "correlation": state.pipeline.correlator.stats.to_dict(),
    }


@router.get("/soc")
async def soc_performance(
    days: int = Query(default=7, ge=1, le=90),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """MTTD/MTTA/MTTR, SLA attainment, queue age and reopen rate.

    Computed from the timestamps case management already records, so there is
    no separate instrumentation to keep in step.
    """
    return state.soc_metrics.report(tenant, days=days)


@router.get("/sla-breaches")
async def sla_breaches(
    limit: int = Query(default=50, ge=1, le=200),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Open incidents past either deadline, worst risk first."""
    breached = state.incidents.sla_breaches(tenant, limit=limit)
    return {
        "count": len(breached),
        "incidents": [
            {
                "key": incident.key,
                "title": incident.title,
                "severity": incident.severity.value,
                "risk_score": incident.risk_score,
                "owner": incident.owner,
                "team_slug": incident.team_slug,
                "sla": state.incidents.sla_state(incident),
            }
            for incident in breached
        ],
    }


@router.get("/notifications")
async def notification_log(
    limit: int = Query(default=50, ge=1, le=200),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Recent notifications and whether they were delivered.

    Persisting before sending is what makes this answerable: "nobody was told"
    and "nobody should have been told" are different situations.
    """
    records = state.incidents.notifier.pending(tenant, limit=limit)
    by_status: Dict[str, int] = {}
    for record in records:
        by_status[record["status"]] = by_status.get(record["status"], 0) + 1
    return {"count": len(records), "by_status": by_status, "notifications": records}
