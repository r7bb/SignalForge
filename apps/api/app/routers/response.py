"""Response playbooks: request, approve, reject, execute.

Requests are open to analysts; approval requires the responder (or admin) role
and cannot be granted by the requester.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from signalforge.auth import Principal
from signalforge.response import list_playbooks
from signalforge.telemetry import RESPONSE_ACTIONS

from ..deps import current_principal, get_state, require_analyst, require_responder, tenant_scope
from ..schemas import ApprovalRequest, ResponseRequest
from ..state import AppState

router = APIRouter(prefix="/response", tags=["response"])


@router.get("/playbooks")
async def playbooks(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    return {"playbooks": list_playbooks()}


@router.get("/actions")
async def list_actions(
    incident_id: Optional[str] = None,
    status_filter: Optional[List[str]] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    return {
        "actions": state.responses.list(
            tenant, incident_id=incident_id, status=status_filter, limit=limit
        )
    }


@router.post("/incidents/{reference}/actions", status_code=201)
async def request_action(
    reference: str,
    payload: ResponseRequest,
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Request a playbook against an incident.  Nothing runs until approval."""
    action = state.responses.request(
        tenant=principal.tenant,
        playbook=payload.playbook,
        actor=principal.email,
        incident_id=reference,
        target=payload.target,
        params=payload.params,
    )
    RESPONSE_ACTIONS.labels(playbook=payload.playbook, status=action["status"]).inc()
    return action


@router.post("/actions/{action_id}/approve")
async def approve(
    action_id: str,
    payload: ApprovalRequest,
    principal: Principal = Depends(require_responder),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    action = state.responses.approve(
        tenant=principal.tenant,
        action_id=action_id,
        actor=principal.email,
        role=principal.role,
        execute_now=payload.execute_now,
    )
    RESPONSE_ACTIONS.labels(playbook=action["playbook"], status=action["status"]).inc()
    return action


@router.post("/actions/{action_id}/reject")
async def reject(
    action_id: str,
    payload: ApprovalRequest,
    principal: Principal = Depends(require_responder),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    action = state.responses.reject(
        tenant=principal.tenant,
        action_id=action_id,
        actor=principal.email,
        reason=payload.reason,
    )
    RESPONSE_ACTIONS.labels(playbook=action["playbook"], status=action["status"]).inc()
    return action


@router.post("/actions/{action_id}/execute")
async def execute_action(
    action_id: str,
    principal: Principal = Depends(require_responder),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    action = state.responses.run(
        tenant=principal.tenant, action_id=action_id, actor=principal.email
    )
    RESPONSE_ACTIONS.labels(playbook=action["playbook"], status=action["status"]).inc()
    return action


@router.get("/actions/{action_id}")
async def get_action(
    action_id: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    from fastapi import HTTPException

    action = state.responses.get(tenant, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="unknown response action %r" % action_id)
    return action


@router.get("/denylist")
async def denylist(
    principal: Principal = Depends(require_responder),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """The local denylist the deny_ip playbook writes to."""
    return {
        "path": str(state.responses.adapter.denylist_path),
        "entries": state.responses.adapter.read_denylist(),
        "dry_run": state.settings.response_dry_run,
    }
