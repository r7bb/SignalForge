"""Incident case management: queue, detail, timeline and analyst workflow."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from signalforge.attack import describe_techniques, kill_chain
from signalforge.auth import Principal
from signalforge.correlate.risk import risk_level
from signalforge.models.incident import ALLOWED_TRANSITIONS, Incident, IncidentStatus
from signalforge.response import list_playbooks, suggest_target

from ..deps import get_state, require_analyst, require_viewer, tenant_scope
from ..routers.alerts import _summary as alert_summary
from ..schemas import (
    AssignRequest,
    ClaimRequest,
    IncidentDetail,
    IncidentSummary,
    NoteRequest,
    TransferRequest,
    TransitionRequest,
    UnclaimRequest,
)
from ..state import AppState

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _summary(incident: Incident) -> Dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "key": incident.key,
        "title": incident.title,
        "status": incident.status.value,
        "severity": incident.severity.value,
        "owner": incident.owner,
        "assignee_id": incident.assignee_id,
        "team_id": incident.team_id,
        "team_slug": incident.team_slug,
        "acknowledged_at": incident.acknowledged_at,
        "waiting_until": incident.waiting_until,
        "waiting_reason": incident.waiting_reason,
        "version": incident.version,
        "risk_score": incident.risk_score,
        "risk_level": risk_level(incident.risk_score),
        "scenario": incident.scenario,
        "principal": incident.principal,
        "source_ips": incident.source_ips,
        "hostnames": incident.hostnames,
        "tactics": kill_chain(incident.tactics),
        "techniques": describe_techniques(incident.techniques),
        "alert_count": len(incident.alert_ids),
        "evidence_count": incident.evidence_count,
        "first_seen": incident.first_seen,
        "last_seen": incident.last_seen,
        "updated_at": incident.updated_at,
    }


def _require(state: AppState, tenant: str, reference: str) -> Incident:
    incident = state.incidents.get(tenant, reference)
    if incident is None:
        if state.incidents.incident_exists_elsewhere(reference, tenant):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="incident belongs to another tenant",
            )
        raise HTTPException(status_code=404, detail="unknown incident %r" % reference)
    return incident


@router.get("", response_model=List[IncidentSummary])
async def list_incidents(
    status_filter: Optional[List[str]] = Query(default=None, alias="status"),
    severity: Optional[List[str]] = Query(default=None),
    owner: Optional[str] = None,
    scenario: Optional[str] = None,
    min_risk: Optional[int] = Query(default=None, ge=0, le=100),
    open_only: bool = False,
    team: Optional[str] = Query(default=None, description="team slug or id"),
    mine: bool = Query(default=False, description="only incidents assigned to me"),
    unclaimed: bool = Query(default=False, description="only unclaimed incidents"),
    order: str = Query(default="risk", pattern="^(risk|oldest)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_viewer),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> List[Dict[str, Any]]:
    team_id = state.teams.require(tenant, team).id if team else None
    incidents = state.incidents.list(
        tenant,
        status=status_filter,
        severity=severity,
        owner=owner,
        scenario=scenario,
        min_risk=min_risk,
        open_only=open_only,
        team_id=team_id,
        assignee_id=principal.user_id if mine else None,
        unassigned_only=unclaimed,
        order=order,
        limit=limit,
        offset=offset,
    )
    return [_summary(incident) for incident in incidents]


@router.get("/{reference}", response_model=IncidentDetail)
async def get_incident(
    reference: str,
    timeline_size: int = Query(default=40, ge=1, le=1000),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """The investigation view: incident, its alerts, timeline, notes and audit."""
    incident = _require(state, tenant, reference)
    alerts = state.incidents.get_alerts(tenant, incident.alert_ids)
    # A focused window by default: the incident's own span plus a few minutes
    # either side. The dedicated /timeline route serves the full history.
    timeline = state.incidents.build_timeline(
        tenant, reference, pad_seconds=300, size=timeline_size
    )
    actions = state.responses.list(tenant, incident_id=incident.incident_id)

    suggested = []
    for playbook in list_playbooks():
        suggested.append(
            {
                **playbook,
                "suggested_target": suggest_target(playbook["name"], incident),
            }
        )

    return {
        **_summary(incident),
        "summary": incident.summary,
        "risk_factors": incident.risk_factors,
        "alerts": [alert_summary(alert) for alert in alerts],
        "timeline": [entry.model_dump(mode="json") for entry in timeline],
        "notes": [note.model_dump(mode="json") for note in incident.notes],
        "audit": [entry.model_dump(mode="json") for entry in incident.audit],
        "response_actions": actions,
        "suggested_playbooks": suggested,
    }


@router.get("/{reference}/timeline")
async def get_timeline(
    reference: str,
    size: int = Query(default=300, ge=1, le=1000),
    pad_minutes: int = Query(default=15, ge=0, le=1440),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, tenant, reference)
    entries = state.incidents.build_timeline(
        tenant, reference, pad_seconds=pad_minutes * 60, size=size
    )
    return {
        "count": len(entries),
        "entries": [entry.model_dump(mode="json") for entry in entries],
    }


@router.get("/{reference}/attack")
async def get_attack_path(
    reference: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    incident = _require(state, tenant, reference)
    return {
        "tactics": kill_chain(incident.tactics),
        "techniques": describe_techniques(incident.techniques),
    }


@router.get("/{reference}/audit")
async def get_audit(
    reference: str,
    limit: int = Query(default=200, ge=1, le=1000),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, tenant, reference)
    return {"entries": state.incidents.audit_trail(tenant, reference, limit=limit)}


@router.post("/{reference}/status", response_model=IncidentSummary)
async def transition(
    reference: str,
    payload: TransitionRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, principal.tenant, reference)
    try:
        target = IncidentStatus(payload.status)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid status %r (expected one of %s)"
            % (payload.status, ", ".join(item.value for item in IncidentStatus)),
        ) from exc
    incident = state.incidents.transition(
        principal.tenant,
        reference,
        target,
        principal.email,
        payload.reason,
        actor_role=principal.role,
        actor_user_id=principal.user_id,
        expected_version=payload.expected_version,
        waiting_until=payload.waiting_until,
    )
    return _summary(incident)


@router.post("/{reference}/claim", response_model=IncidentSummary)
async def claim(
    reference: str,
    payload: ClaimRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Take personal ownership. 409 if somebody else already holds it."""
    _require(state, principal.tenant, reference)
    incident = state.incidents.claim(
        principal.tenant,
        reference,
        user_id=principal.user_id,
        email=principal.email,
        expected_version=payload.expected_version,
        force=payload.force,
    )
    return _summary(incident)


@router.post("/{reference}/unclaim", response_model=IncidentSummary)
async def unclaim(
    reference: str,
    payload: UnclaimRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, principal.tenant, reference)
    incident = state.incidents.unclaim(
        principal.tenant,
        reference,
        actor=principal.email,
        reason=payload.reason,
        expected_version=payload.expected_version,
    )
    return _summary(incident)


@router.post("/{reference}/transfer", response_model=IncidentSummary)
async def transfer(
    reference: str,
    payload: TransferRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Move an incident to another queue. The reason is mandatory."""
    _require(state, principal.tenant, reference)
    team = state.teams.require(principal.tenant, payload.team)
    incident = state.incidents.transfer(
        principal.tenant,
        reference,
        team_id=team.id,
        team_slug=team.slug,
        reason=payload.reason,
        actor=principal.email,
        expected_version=payload.expected_version,
        keep_assignee=payload.keep_assignee,
    )
    return _summary(incident)


@router.get("/{reference}/transitions")
async def allowed_transitions(
    reference: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    incident = _require(state, tenant, reference)
    return {
        "status": incident.status.value,
        "allowed": sorted(item.value for item in ALLOWED_TRANSITIONS.get(incident.status, set())),
    }


@router.post("/{reference}/assign", response_model=IncidentSummary)
async def assign(
    reference: str,
    payload: AssignRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, principal.tenant, reference)
    incident = state.incidents.assign(principal.tenant, reference, payload.owner, principal.email)
    return _summary(incident)


@router.post("/{reference}/notes", response_model=IncidentDetail)
async def add_note(
    reference: str,
    payload: NoteRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    _require(state, principal.tenant, reference)
    state.incidents.add_note(principal.tenant, reference, principal.email, payload.body)
    return await get_incident(reference, 200, principal.tenant, state)
