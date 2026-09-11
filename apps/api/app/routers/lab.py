"""Lab telemetry: seed the platform and replay benign attack-shape scenarios.

Everything here generates *log records* inside SignalForge's own pipeline.  No
scenario touches a system outside this deployment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from signalforge.auth import Principal
from signalforge.lab import SCENARIOS, TelemetryGenerator, list_scenarios
from signalforge.telemetry import record_pipeline_metrics

from ..deps import current_principal, get_state, require_analyst
from ..schemas import SimulateRequest
from ..state import AppState

router = APIRouter(prefix="/lab", tags=["lab"])


@router.get("/scenarios")
async def scenarios(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    return {"scenarios": list_scenarios()}


@router.post("/simulate")
async def simulate(
    payload: SimulateRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Generate telemetry and run it through the live pipeline."""
    if payload.scenario and payload.scenario not in SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail="unknown scenario %r (available: %s)"
            % (payload.scenario, ", ".join(sorted(SCENARIOS))),
        )

    generator = TelemetryGenerator(tenant=principal.tenant, seed=payload.seed)
    start = datetime.now(tz=timezone.utc) - timedelta(minutes=payload.minutes_ago)

    records = []
    if payload.normal_events:
        records.extend(
            generator.normal_activity(
                payload.normal_events, start, spread_seconds=max(payload.minutes_ago * 60, 60)
            )
        )
    if payload.scenario:
        records.extend(generator.scenario(payload.scenario, start))
    elif not payload.normal_events:
        records.extend(generator.full_demo(start))

    records.sort(key=lambda record: record.received_at)
    result = state.pipeline.ingest(records)
    record_pipeline_metrics(result)

    expected: List[str] = []
    if payload.scenario:
        expected = SCENARIOS[payload.scenario].expected_detections

    fired = sorted({alert.rule_id for alert in result.alerts})
    counts = dict(result.counts)
    return {
        "scenario": payload.scenario or "full_demo",
        "records": len(records),
        "events": counts["events"],
        "alerts": counts["alerts"],
        "correlation_count": counts["correlations"],
        "incident_count": counts["incidents"],
        "dlq": counts["dlq"],
        "duplicates": counts["duplicates"],
        "duration_ms": counts["duration_ms"],
        "detections_fired": fired,
        "expected_detections": expected,
        "expected_not_fired": [rule_id for rule_id in expected if rule_id not in fired],
        "correlations": [
            {
                "id": hit.correlation.id,
                "title": hit.correlation.title,
                "scenario": hit.scenario,
                "alerts": len(hit.alerts),
                "sequence": hit.sequence,
            }
            for hit in result.hits
        ],
        "incidents": [
            {
                "key": incident.key,
                "title": incident.title,
                "risk_score": incident.risk_score,
                "severity": incident.severity.value,
                "incident_id": incident.incident_id,
            }
            for incident in result.incidents
        ],
    }


@router.post("/reset")
async def reset_windows(
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Clear detection/correlation window state (events and cases are kept)."""
    state.pipeline.reset()
    return {"status": "reset", "stats": state.pipeline.stats}
