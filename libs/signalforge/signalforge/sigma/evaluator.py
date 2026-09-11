"""Streaming evaluation of Sigma rules against normalized events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models.ocsf import OcsfEvent, flatten_event
from .condition import And, Node, Not, Or, SearchRef, Wildcard
from .pipeline import event_matches_logsource
from .rule import SigmaRule


@dataclass
class MatchResult:
    """Outcome of evaluating one rule against one event."""

    matched: bool
    rule_id: str = ""
    matched_selections: List[str] = field(default_factory=list)
    matched_fields: Dict[str, Any] = field(default_factory=dict)
    #: True when the rule has an aggregation, so the engine still has to decide
    #: whether the threshold is crossed over the rule's timeframe.
    requires_aggregation: bool = False

    def __bool__(self) -> bool:
        return self.matched


def evaluate_node(
    node: Node, searches: Dict[str, Any], flat: Dict[str, Any], hits: Dict[str, bool]
) -> bool:
    """Evaluate a condition AST node, memoizing per-search results."""

    def search_hit(name: str) -> bool:
        if name not in hits:
            search = searches.get(name)
            hits[name] = bool(search and search.match(flat))
        return hits[name]

    if isinstance(node, SearchRef):
        return search_hit(node.name)
    if isinstance(node, Wildcard):
        results = (search_hit(name) for name in node.resolved)
        return all(results) if node.quantifier == "all" else any(results)
    if isinstance(node, And):
        return all(evaluate_node(child, searches, flat, hits) for child in node.children)
    if isinstance(node, Or):
        return any(evaluate_node(child, searches, flat, hits) for child in node.children)
    if isinstance(node, Not):
        return not evaluate_node(node.child, searches, flat, hits)
    raise TypeError("unknown condition node %r" % type(node).__name__)


def evaluate_flat(rule: SigmaRule, flat: Dict[str, Any]) -> MatchResult:
    """Evaluate a rule against an already-flattened event."""
    hits: Dict[str, bool] = {}
    matched = evaluate_node(rule.condition.expression, rule.searches, flat, hits)
    if not matched:
        return MatchResult(matched=False, rule_id=rule.id)

    matched_selections = [name for name, hit in hits.items() if hit]
    evidence: Dict[str, Any] = {}
    for name in matched_selections:
        evidence.update(rule.searches[name].matched_fields(flat))
    for field_name in rule.fields:
        if field_name in flat and field_name not in evidence:
            evidence[field_name] = flat[field_name]
    return MatchResult(
        matched=True,
        rule_id=rule.id,
        matched_selections=sorted(matched_selections),
        matched_fields=evidence,
        requires_aggregation=rule.is_stateful,
    )


def evaluate(
    rule: SigmaRule, event: OcsfEvent, flat: Optional[Dict[str, Any]] = None
) -> MatchResult:
    """Evaluate a rule against an OCSF event (logsource prefilter included)."""
    if not event_matches_logsource(rule, event):
        return MatchResult(matched=False, rule_id=rule.id)
    return evaluate_flat(rule, flat if flat is not None else flatten_event(event))
