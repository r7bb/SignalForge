"""Detection registry: browse rules, lint them, preview and retro-hunt."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from signalforge.auth import Principal
from signalforge.sigma import compile_rule, lint_rules, load_rule_tests
from signalforge.sigma.rule import SigmaCorrelationRule, SigmaRule
from signalforge.storage import db as dbm
from sqlalchemy import select

from ..deps import current_principal, get_state, require_admin, tenant_scope
from ..schemas import RetroHuntRequest, RuleSummary
from ..state import AppState

router = APIRouter(prefix="/detections", tags=["detections"])


def _summarize(rule: Any, revision: Optional[int] = None) -> Dict[str, Any]:
    is_correlation = isinstance(rule, SigmaCorrelationRule)
    return {
        "id": rule.id,
        "name": rule.name,
        "title": rule.title,
        "kind": "correlation" if is_correlation else "detection",
        "level": rule.level,
        "status": rule.status,
        "description": rule.description,
        "author": getattr(rule, "author", None),
        "logsource": rule.logsource.as_dict() if isinstance(rule, SigmaRule) else {},
        "tactics": rule.tactics,
        "techniques": rule.techniques,
        "falsepositives": rule.falsepositives,
        "stateful": rule.is_stateful if isinstance(rule, SigmaRule) else True,
        "timeframe_seconds": (rule.timeframe if isinstance(rule, SigmaRule) else rule.timespan),
        "condition": rule.condition.source if isinstance(rule, SigmaRule) else None,
        "correlation_type": None if isinstance(rule, SigmaRule) else rule.type,
        "correlation_rules": [] if isinstance(rule, SigmaRule) else rule.rule_refs,
        "source_path": rule.source_path,
        "revision": revision,
    }


def _revisions(state: AppState) -> Dict[str, int]:
    factory = dbm.get_session_factory(state.settings)
    with factory() as session:
        return {row.rule_id: row.revision for row in session.scalars(select(dbm.Detection)).all()}


@router.get("", response_model=List[RuleSummary])
async def list_detections(
    kind: Optional[str] = Query(default=None, pattern="^(detection|correlation)$"),
    level: Optional[List[str]] = Query(default=None),
    tactic: Optional[str] = None,
    search: Optional[str] = None,
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> List[Dict[str, Any]]:
    revisions = _revisions(state)
    rules: List[Any] = []
    if kind in (None, "detection"):
        rules.extend(state.ruleset.rules.values())
    if kind in (None, "correlation"):
        rules.extend(state.ruleset.correlations.values())

    out = []
    for rule in rules:
        if level and rule.level not in level:
            continue
        if tactic and tactic.lower() not in [t.lower() for t in rule.tactics]:
            continue
        if search:
            haystack = " ".join(
                filter(None, [rule.id, rule.name or "", rule.title, rule.description or ""])
            ).lower()
            if search.lower() not in haystack:
                continue
        out.append(_summarize(rule, revisions.get(rule.id)))
    return sorted(out, key=lambda item: (item["kind"], item["id"]))


@router.get("/lint")
async def lint(
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Run the rule linter over the detection directory (the CI gate)."""
    report = lint_rules(state.settings.detections_path)
    return report.to_dict()


@router.post("/reload")
async def reload_rules(
    principal: Principal = Depends(require_admin),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    result = state.reload_rules()
    result["registry_updates"] = state.sync_detection_registry()
    return result


@router.post("/retro-hunt")
async def retro_hunt(
    payload: RetroHuntRequest,
    tenant: str = Depends(tenant_scope),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Run an existing detection over historical events in the event store."""
    rule = state.ruleset.rules.get(payload.rule_id)
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail="unknown detection %r (correlation rules cannot be retro-hunted directly)"
            % payload.rule_id,
        )
    body = compile_rule(
        rule,
        tenant=tenant,
        earliest=payload.earliest,
        latest=payload.latest,
        size=payload.size,
    )
    response = state.event_store.raw_search(body)
    hits = response.get("hits", {})
    total = hits.get("total", {})
    buckets = (
        response.get("aggregations", {}).get("grouped", {}).get("buckets", [])
        if "aggregations" in response
        else []
    )
    return {
        "rule_id": rule.id,
        "rule_title": rule.title,
        "query": body,
        "total": total.get("value", 0) if isinstance(total, dict) else int(total or 0),
        "groups": buckets,
        "events": [hit.get("_source") for hit in hits.get("hits", [])],
    }


@router.get("/{rule_id}")
async def get_detection(
    rule_id: str,
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    rule = state.ruleset.resolve(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="unknown detection %r" % rule_id)
    payload = _summarize(rule, _revisions(state).get(rule.id))
    payload["document"] = rule.raw
    payload["references"] = getattr(rule, "references", [])
    if isinstance(rule, SigmaRule):
        payload["searches"] = {name: search.fields for name, search in rule.searches.items()}
        payload["opensearch_query"] = compile_rule(rule, tenant=principal.tenant)
    if rule.source_path:
        payload["tests"] = load_rule_tests(rule.source_path)
    correlations = state.ruleset.correlations_referencing(rule.id)
    payload["referenced_by"] = [
        {"id": correlation.id, "title": correlation.title, "type": correlation.type}
        for correlation in correlations
    ]
    return payload


@router.get("/{rule_id}/versions")
async def get_versions(
    rule_id: str,
    principal: Principal = Depends(current_principal),
    state: AppState = Depends(get_state),
) -> Dict[str, Any]:
    """Rule history - every edit produces a new revision in the registry."""
    factory = dbm.get_session_factory(state.settings)
    with factory() as session:
        detection = session.scalars(
            select(dbm.Detection).where(dbm.Detection.rule_id == rule_id)
        ).first()
        if detection is None:
            raise HTTPException(status_code=404, detail="unknown detection %r" % rule_id)
        versions = session.scalars(
            select(dbm.DetectionVersion)
            .where(dbm.DetectionVersion.detection_id == detection.id)
            .order_by(dbm.DetectionVersion.revision.desc())
        ).all()
        return {
            "rule_id": rule_id,
            "current_revision": detection.revision,
            "content_hash": detection.content_hash,
            "versions": [
                {
                    "revision": version.revision,
                    "content_hash": version.content_hash,
                    "author": version.author,
                    "created_at": version.created_at,
                }
                for version in versions
            ],
        }
