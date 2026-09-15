"""Incident routing: the table, and why a given incident landed where it did."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from signalforge.routing import RoutingFacts

from ..deps import get_state, require_viewer, tenant_scope
from ..state import AppState

router = APIRouter(prefix="/routing", tags=["routing"])


class PreviewRequest(BaseModel):
    """Either point at an existing incident, or describe a hypothetical one."""

    incident: Optional[str] = None
    scenario: Optional[str] = None
    severity: Optional[str] = None
    risk_score: int = 0
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    rule_ids: List[str] = Field(default_factory=list)
    principal: Optional[str] = None
    hostnames: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)


def _rule_payload(rule: Any) -> Dict[str, Any]:
    return {
        "id": rule.id,
        "team": rule.team,
        "priority": rule.priority,
        "title": rule.title,
        "description": rule.description,
        "enabled": rule.enabled,
        "match": rule.match,
        "match_summary": rule.describe(),
        "is_catch_all": rule.is_catch_all,
        "source_path": rule.source_path,
    }


@router.get("")
async def list_routing(
    _: Any = Depends(require_viewer),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """The routing table in the order it is evaluated."""
    table = state.incidents.routing
    return {
        "rules": [_rule_payload(rule) for rule in table.rules],
        "count": len(table.rules),
        "errors": table.errors,
        "enabled": state.settings.routing_enabled,
        "path": state.settings.routing_path,
    }


@router.post("/preview")
async def preview_routing(
    payload: PreviewRequest,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Which queue would this land in, and which rule decided?

    Answers the two questions a routing change raises: "where does this go now"
    and "what else did I just change" - the second one being why every rule is
    returned with its verdict rather than only the winner.
    """
    if payload.incident:
        incident = state.incidents.get(tenant, payload.incident)
        if incident is None:
            raise HTTPException(status_code=404, detail="unknown incident %r" % payload.incident)
        # Pass the linked alerts explicitly: the incident model carries
        # alert_ids, not the alert objects the detection ids live on.
        alerts = state.incidents.get_alerts(tenant, incident.alert_ids)
        facts = RoutingFacts.from_incident(incident, alerts)
    else:
        facts = RoutingFacts(
            tenant=tenant,
            scenario=payload.scenario,
            severity=payload.severity,
            risk_score=payload.risk_score,
            tactics=tuple(payload.tactics),
            techniques=tuple(payload.techniques),
            rule_ids=tuple(payload.rule_ids),
            principal=payload.principal,
            hostnames=tuple(payload.hostnames),
            source_ips=tuple(payload.source_ips),
        )

    table = state.incidents.routing
    winner = table.match(facts)
    default_team = state.teams.default_team(tenant)

    return {
        "matched": _rule_payload(winner) if winner else None,
        "team": winner.team if winner else (default_team.slug if default_team else None),
        "via": "rule" if winner else ("default_queue" if default_team else "unrouted"),
        "evaluated": [
            {"id": rule.id, "team": rule.team, "priority": rule.priority, "matched": matched}
            for rule, matched in table.explain(facts)
        ],
    }
