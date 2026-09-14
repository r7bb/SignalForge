"""Teams and the queue views built on them."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from signalforge.auth import Principal
from signalforge.models.incident import ACTIVE_STATUSES
from signalforge.models.team import Team

from ..deps import get_state, require_admin, require_analyst, tenant_scope
from ..schemas import TeamMemberRequest, TeamRequest
from ..state import AppState

router = APIRouter(prefix="/teams", tags=["teams"])


def _team_payload(team: Team) -> Dict[str, Any]:
    return {
        "id": team.id,
        "slug": team.slug,
        "name": team.name,
        "description": team.description,
        "is_default": team.is_default,
        "open_incidents": team.open_incidents,
        "unclaimed_incidents": team.unclaimed_incidents,
        "members": [
            {
                "user_id": member.user_id,
                "email": member.email,
                "full_name": member.full_name,
                "role": member.role,
            }
            for member in team.members
        ],
    }


@router.get("")
async def list_teams(
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    teams = state.teams.list(tenant)
    return {"teams": [_team_payload(team) for team in teams], "count": len(teams)}


@router.post("", status_code=201)
async def create_team(
    payload: TeamRequest,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    team = state.teams.create(
        principal.tenant,
        payload.name,
        slug=payload.slug,
        description=payload.description,
        is_default=payload.is_default,
        actor=principal.email,
    )
    return _team_payload(team)


@router.get("/mine")
async def my_teams(
    principal: Principal = Depends(require_analyst),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """The queues this analyst belongs to - what the dashboard defaults to."""
    teams = state.teams.teams_for_user(principal.tenant, principal.user_id)
    leads = set(state.teams.leads_of(principal.tenant, principal.user_id))
    return {
        "teams": [dict(_team_payload(team), is_lead=team.id in leads) for team in teams],
        "count": len(teams),
    }


@router.get("/{slug}")
async def get_team(
    slug: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    team = state.teams.require(tenant, slug)
    # require() raises TeamError -> 404 when the slug is unknown.
    with_counts = state.teams.get(tenant, slug, with_counts=True) or team
    return _team_payload(with_counts)


@router.delete("/{slug}", status_code=204)
async def delete_team(
    slug: str,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> None:
    state.teams.delete(principal.tenant, slug, actor=principal.email)


@router.post("/{slug}/default")
async def make_default(
    slug: str,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    team = state.teams.set_default(principal.tenant, slug, actor=principal.email)
    return _team_payload(team)


@router.post("/{slug}/members", status_code=201)
async def add_member(
    slug: str,
    payload: TeamMemberRequest,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    member = state.teams.add_member(
        principal.tenant, slug, payload.user, role=payload.role, actor=principal.email
    )
    return {
        "user_id": member.user_id,
        "email": member.email,
        "role": member.role,
        "team": slug,
    }


@router.delete("/{slug}/members/{user}", status_code=204)
async def remove_member(
    slug: str,
    user: str,
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> None:
    state.teams.remove_member(principal.tenant, slug, user, actor=principal.email)


@router.get("/{slug}/queue")
async def team_queue(
    slug: str,
    unclaimed_only: bool = Query(False, description="only work nobody has picked up"),
    limit: int = Query(50, ge=1, le=500),
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """A team's open work, oldest first.

    Oldest-first is deliberate and the opposite of the risk-ranked incident
    list: a queue is worked from the bottom, and the oldest unclaimed item is
    the one most likely to breach.
    """
    team = state.teams.require(tenant, slug)
    incidents = state.incidents.list(
        tenant,
        status=[status.value for status in ACTIVE_STATUSES],
        team_id=team.id,
        unassigned_only=unclaimed_only,
        order="oldest",
        limit=limit,
    )
    return {
        "team": {"slug": team.slug, "name": team.name, "id": team.id},
        "incidents": [
            {
                "key": incident.key,
                "title": incident.title,
                "status": incident.status.value,
                "severity": incident.severity.value,
                "risk_score": incident.risk_score,
                "owner": incident.owner,
                "principal": incident.principal,
                "first_seen": incident.first_seen,
                "acknowledged_at": incident.acknowledged_at,
                "waiting_until": incident.waiting_until,
                "version": incident.version,
            }
            for incident in incidents
        ],
        "count": len(incidents),
    }


@router.get("/{slug}/handover")
async def handover(
    slug: str,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """What one shift hands to the next: every open case with its last action."""
    team = state.teams.require(tenant, slug)
    incidents = state.incidents.list(
        tenant,
        status=[status.value for status in ACTIVE_STATUSES],
        team_id=team.id,
        order="oldest",
        limit=200,
    )
    rows: List[Dict[str, Any]] = []
    for incident in incidents:
        trail = state.incidents.audit_trail(tenant, reference=incident.key, limit=1)
        last = trail[0] if trail else None
        rows.append(
            {
                "key": incident.key,
                "title": incident.title,
                "status": incident.status.value,
                "risk_score": incident.risk_score,
                "owner": incident.owner or "unclaimed",
                "waiting_until": incident.waiting_until,
                "last_action": (last or {}).get("action"),
                "last_actor": (last or {}).get("actor"),
                "last_action_at": (last or {}).get("time"),
            }
        )
    return {
        "team": {"slug": team.slug, "name": team.name},
        "open_incidents": len(rows),
        "unclaimed": sum(1 for row in rows if row["owner"] == "unclaimed"),
        "incidents": rows,
    }
