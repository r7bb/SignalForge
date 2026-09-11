"""Threat-intelligence lookups."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from signalforge.auth import Principal
from signalforge.telemetry import INTEL_LOOKUPS

from ..deps import current_principal, get_state
from ..state import AppState

router = APIRouter(prefix="/intel", tags=["intel"])

INDICATOR_TYPES = ("ip", "domain", "url", "file_hash")


@router.get("/lookup")
async def lookup(
    value: str,
    type: str = Query(default="ip", pattern="^(ip|domain|url|file_hash)$"),
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    report = state.intel.lookup(value, type)
    INTEL_LOOKUPS.labels(
        provider=",".join(report.providers) or "none",
        cache="hit" if report.cached else "miss",
    ).inc()
    return report.to_dict()


@router.post("/lookup/bulk")
async def lookup_bulk(
    values: List[str],
    type: str = Query(default="ip", pattern="^(ip|domain|url|file_hash)$"),
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Bulk lookup; repeated indicators are served from the cache."""
    reports = [state.intel.lookup(value, type) for value in values[:200]]
    return {
        "count": len(reports),
        "cache_hits": sum(1 for report in reports if report.cached),
        "results": [report.to_dict() for report in reports],
    }


@router.get("/providers")
async def providers(
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return {
        "providers": [provider.name for provider in state.intel.providers],
        "cache": state.intel.cache_stats,
        "http_enabled": state.settings.intel_http_enabled,
        "feed_path": state.settings.intel_feed_path,
        "cache_ttl_seconds": state.settings.intel_cache_ttl_seconds,
    }
