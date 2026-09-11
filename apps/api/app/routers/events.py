"""Ingestion and security-event search."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from signalforge.auth import Principal
from signalforge.models.ocsf import RawLogRecord
from signalforge.storage.events import EventQuery
from signalforge.telemetry import END_TO_END_LATENCY, EVENTS_INGESTED, record_pipeline_metrics

from ..deps import current_principal, get_state, require_analyst, tenant_scope
from ..schemas import (
    EventSearchRequest,
    EventSearchResponse,
    IngestRequest,
    IngestResponse,
)
from ..state import AppState

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest(
    payload: IngestRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Normalize, store and (by default) run detections over a batch of records.

    Collectors normally publish to the bus and the worker services do this;
    this endpoint is the synchronous path used by the lab generator, the load
    harness and anything that wants the alerts in the response.
    """
    if not payload.records:
        raise HTTPException(status_code=400, detail="no records supplied")

    records: List[RawLogRecord] = []
    for item in payload.records:
        EVENTS_INGESTED.labels(source=item.source, tenant=principal.tenant).inc()
        records.append(
            RawLogRecord(
                source=item.source,
                tenant=principal.tenant,
                payload=item.payload,
                raw=item.raw,
                collector=item.collector or "api",
                received_at=item.received_at or datetime.now(tz=timezone.utc),
            )
        )

    if payload.detect:
        result = state.pipeline.ingest(records)
    else:
        from signalforge.normalize import registry

        events, failures = registry.normalize_many(records)
        from signalforge.pipeline import PipelineResult

        result = PipelineResult(events=events, dlq=failures)
        if events:
            result.index_result = state.event_store.index(events)

    record_pipeline_metrics(result)
    END_TO_END_LATENCY.observe(result.duration_ms / 1000.0)
    return {
        "accepted": len(records),
        **result.counts,
        "incident_keys": result.incident_keys(),
        "alert_ids": [alert.alert_id for alert in result.alerts],
    }


@router.post("/search", response_model=EventSearchResponse)
async def search(
    payload: EventSearchRequest,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    query = EventQuery(
        tenant=tenant,
        text=payload.text,
        class_uids=payload.class_uids,
        principal=payload.principal,
        source_ip=payload.source_ip,
        hostname=payload.hostname,
        session_uid=payload.session_uid,
        status_id=payload.status_id,
        min_severity_id=payload.min_severity_id,
        start=payload.start,
        end=payload.end,
        size=payload.size,
        offset=payload.offset,
        ascending=payload.ascending,
    )
    result = state.event_store.search(query)
    return {
        "total": result.total,
        "took_ms": result.took_ms,
        "events": [event.to_document() for event in result.events],
    }


@router.get("/timeline")
async def timeline(
    principal_filter: Optional[str] = Query(default=None, alias="principal"),
    source_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    session_uid: Optional[str] = None,
    minutes: int = Query(default=60, ge=1, le=10080),
    size: int = Query(default=200, ge=1, le=1000),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Every event touching an entity, ordered by event time."""
    if not any([principal_filter, source_ip, hostname, session_uid]):
        raise HTTPException(
            status_code=400,
            detail="supply at least one of principal, source_ip, hostname, session_uid",
        )
    end = datetime.now(tz=timezone.utc)
    events = state.event_store.timeline(
        tenant,
        principals=[principal_filter] if principal_filter else [],
        source_ips=[source_ip] if source_ip else [],
        hostnames=[hostname] if hostname else [],
        session_uids=[session_uid] if session_uid else [],
        start=end - timedelta(minutes=minutes),
        end=end,
        size=size,
    )
    return {
        "count": len(events),
        "events": [event.to_document() for event in events],
    }


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    event = state.event_store.get(event_id, tenant)
    if event is None:
        raise HTTPException(status_code=404, detail="unknown event %r" % event_id)
    return event.to_document()


@router.get("/sources/registry")
async def sources(
    principal: Principal = Depends(current_principal),
) -> Dict[str, Any]:
    """Which source keys the normalizer understands."""
    from signalforge.normalize import registry as mapper_registry

    return {"sources": mapper_registry.describe()}
