"""Liveness, readiness and pipeline introspection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends
from signalforge.telemetry import snapshot

from ..deps import current_principal, get_state
from ..state import AppState

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(state: AppState = Depends(get_state)) -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": "0.1.0",
        "environment": state.settings.environment,
        "uptime_seconds": int((datetime.now(tz=timezone.utc) - state.started_at).total_seconds()),
        "backends": {
            "event_store": state.settings.event_store_backend,
            "bus": state.settings.bus_backend,
            "database": state.settings.database_url.split("://", 1)[0],
            "cache": "redis" if state.settings.redis_url else "memory",
        },
        "rules": {
            "detections": len(state.ruleset.rules),
            "correlations": len(state.ruleset.correlations),
            "load_errors": len(state.ruleset.errors),
        },
    }


@router.get("/health/live")
async def live() -> Dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
async def ready(state: AppState = Depends(get_state)) -> Dict[str, Any]:
    """Ready only when rules loaded cleanly and the event store answers."""
    store_ok = True
    detail = None
    try:
        state.event_store.stats(state.settings.bootstrap_tenant)
    except Exception as exc:  # pragma: no cover - depends on the backend
        store_ok = False
        detail = str(exc)
    ready_now = store_ok and bool(state.ruleset.rules) and not state.ruleset.errors
    return {
        "status": "ready" if ready_now else "degraded",
        "event_store": "ok" if store_ok else "unavailable",
        "detail": detail,
        "rule_errors": [{"path": path, "error": error} for path, error in state.ruleset.errors],
    }


@router.get("/pipeline/stats")
async def pipeline_stats(
    state: AppState = Depends(get_state),
    principal: Any = Depends(current_principal),
) -> Dict[str, Any]:
    return snapshot(state.pipeline)
