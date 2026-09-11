"""Alert queue."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from signalforge.auth import Principal
from signalforge.models.alert import Alert, AlertStatus

from ..deps import get_state, require_analyst, tenant_scope
from ..schemas import AlertSummary
from ..state import AppState

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _summary(alert: Alert) -> Dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_title": alert.rule_title,
        "rule_level": alert.rule_level,
        "status": alert.status.value if isinstance(alert.status, AlertStatus) else alert.status,
        "risk_score": alert.risk_score,
        "risk_level": alert.risk_level,
        "principal": alert.principal,
        "source_ip": alert.source_ip,
        "hostname": alert.hostname,
        "occurrences": alert.occurrences,
        "is_building_block": alert.is_building_block,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "tactics": alert.tactics,
        "techniques": alert.techniques,
        "incident_id": alert.incident_id,
    }


@router.get("", response_model=List[AlertSummary])
async def list_alerts(
    status_filter: Optional[List[str]] = Query(default=None, alias="status"),
    risk_level: Optional[List[str]] = Query(default=None),
    rule_id: Optional[str] = None,
    principal_filter: Optional[str] = Query(default=None, alias="principal"),
    source_ip: Optional[str] = None,
    min_risk: Optional[int] = Query(default=None, ge=0, le=100),
    hours: Optional[int] = Query(default=None, ge=1, le=8760),
    include_building_blocks: bool = Query(
        default=False,
        description="Include correlation building blocks (informational, high volume)",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> List[Dict[str, Any]]:
    since = datetime.now(tz=timezone.utc) - timedelta(hours=hours) if hours else None
    alerts = state.incidents.list_alerts(
        tenant,
        status=status_filter,
        risk_level=risk_level,
        rule_id=rule_id,
        principal=principal_filter,
        source_ip=source_ip,
        min_risk=min_risk,
        since=since,
        include_building_blocks=include_building_blocks,
        limit=limit,
        offset=offset,
    )
    return [_summary(alert) for alert in alerts]


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    alert = state.incidents.get_alert(tenant, alert_id)
    if alert is None:
        # Distinguish "not yours" from "does not exist" - a cross-tenant read is
        # a permission problem, not a missing resource.
        if state.incidents.alert_exists_elsewhere(alert_id, tenant):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="alert belongs to another tenant",
            )
        raise HTTPException(status_code=404, detail="unknown alert %r" % alert_id)
    payload = alert.model_dump(mode="json")
    rule = state.ruleset.rules.get(alert.rule_id) or state.ruleset.correlations.get(alert.rule_id)
    if rule is not None:
        payload["rule"] = {
            "id": rule.id,
            "name": rule.name,
            "title": rule.title,
            "level": rule.level,
            "status": rule.status,
            "description": rule.description,
            "falsepositives": rule.falsepositives,
            "source_path": rule.source_path,
        }
    return payload


@router.post("/{alert_id}/status")
async def set_status(
    alert_id: str,
    new_status: str = Query(alias="status"),
    reason: Optional[str] = None,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    try:
        target = AlertStatus(new_status)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid status %r (expected one of %s)"
            % (new_status, ", ".join(item.value for item in AlertStatus)),
        ) from exc
    alert = state.incidents.set_alert_status(
        principal.tenant, alert_id, target, principal.email, reason
    )
    return _summary(alert)
