"""Incident routing: which queue does a new incident belong to?

Routing lives in git, in ``routing/*.yml``, for the same reasons detections do.
"Which team owns cloud credential theft?" is a decision worth reviewing, worth
a commit message, and worth a test - not worth a dropdown somebody changed once
and nobody remembers.

The model is deliberately the simplest thing that is still honest:

* every rule declares a ``priority``; lower numbers are considered first;
* the **first** matching rule wins, so overlap is resolved by priority rather
  than by dictionary order or file name;
* a rule with no ``match`` block matches everything, which is how a catch-all
  is written;
* if nothing matches, the caller falls back to the tenant's default queue.

A match block ANDs its conditions and ORs the values inside each one:

.. code-block:: yaml

    match:
      scenario: [account_compromise, brute_force_success]   # any of these
      min_risk: 70                                          # and at least this
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

logger = logging.getLogger("signalforge.routing")

#: Condition keys a match block may use. Anything else is a typo, and a typo in
#: a routing rule is a rule that silently never fires - so the loader rejects it.
MATCH_KEYS = frozenset(
    {
        "scenario",
        "tactic",
        "technique",
        "rule_id",
        "severity",
        "min_risk",
        "max_risk",
        "principal",
        "hostname",
        "source_ip",
        "tenant",
    }
)


class RoutingError(Exception):
    """A malformed routing rule. Raised at load time, never at match time."""


@dataclass(frozen=True)
class RoutingRule:
    id: str
    team: str
    priority: int = 100
    title: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    match: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[str] = None

    @property
    def is_catch_all(self) -> bool:
        return not self.match

    def matches(self, facts: RoutingFacts) -> bool:
        if not self.enabled:
            return False
        # Conditions are ANDed: every one in the block has to hold.
        return all(_condition_holds(key, expected, facts) for key, expected in self.match.items())

    def describe(self) -> str:
        if self.is_catch_all:
            return "anything"
        return ", ".join(
            "%s=%s" % (key, value if not isinstance(value, list) else "|".join(map(str, value)))
            for key, value in sorted(self.match.items())
        )


@dataclass(frozen=True)
class RoutingFacts:
    """What routing decides on, extracted from an incident.

    A dedicated structure rather than the Incident model so routing can be
    evaluated before an incident exists - which is what the preview endpoint
    and the linter both need.
    """

    tenant: str = "default"
    scenario: Optional[str] = None
    severity: Optional[str] = None
    risk_score: int = 0
    tactics: Sequence[str] = ()
    techniques: Sequence[str] = ()
    rule_ids: Sequence[str] = ()
    principal: Optional[str] = None
    hostnames: Sequence[str] = ()
    source_ips: Sequence[str] = ()

    @classmethod
    def from_incident(cls, incident: Any, alerts: Optional[Sequence[Any]] = None) -> RoutingFacts:
        """Extract the routing facts from an incident.

        ``alerts`` must be passed when routing a *new* incident: at that point
        it carries ``alert_ids`` but not the alert objects, so the detection ids
        - the most reliable routing signal there is - would otherwise be empty.
        """
        candidates = alerts if alerts is not None else getattr(incident, "alerts", None) or []
        return cls(
            tenant=getattr(incident, "tenant", "default"),
            scenario=getattr(incident, "scenario", None),
            severity=_enum_value(getattr(incident, "severity", None)),
            risk_score=int(getattr(incident, "risk_score", 0) or 0),
            tactics=tuple(getattr(incident, "tactics", ()) or ()),
            techniques=tuple(getattr(incident, "techniques", ()) or ()),
            rule_ids=tuple(
                alert.rule_id for alert in candidates if getattr(alert, "rule_id", None)
            ),
            principal=getattr(incident, "principal", None),
            hostnames=tuple(getattr(incident, "hostnames", ()) or ()),
            source_ips=tuple(getattr(incident, "source_ips", ()) or ()),
        )


@dataclass
class RoutingTable:
    rules: List[RoutingRule] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Sorted once at construction: priority first, then id so that two
        # rules at the same priority resolve deterministically rather than by
        # whichever file the OS listed first.
        self.rules.sort(key=lambda rule: (rule.priority, rule.id))

    def match(self, facts: RoutingFacts) -> Optional[RoutingRule]:
        for rule in self.rules:
            if rule.matches(facts):
                return rule
        return None

    def explain(self, facts: RoutingFacts) -> List[Tuple[RoutingRule, bool]]:
        """Every rule with whether it matched - for the preview endpoint."""
        return [(rule, rule.matches(facts)) for rule in self.rules]

    @property
    def enabled_rules(self) -> List[RoutingRule]:
        return [rule for rule in self.rules if rule.enabled]


def _enum_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "value", value)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _any_glob(patterns: Iterable[str], candidates: Iterable[str]) -> bool:
    candidate_list = [c for c in candidates if c]
    return any(
        fnmatch.fnmatch(candidate.lower(), pattern.lower())
        for pattern in patterns
        for candidate in candidate_list
    )


def _condition_holds(key: str, expected: Any, facts: RoutingFacts) -> bool:
    if key == "min_risk":
        return facts.risk_score >= int(expected)
    if key == "max_risk":
        return facts.risk_score <= int(expected)
    if key == "scenario":
        return _any_glob(_as_list(expected), [facts.scenario or ""])
    if key == "severity":
        return (facts.severity or "") in {s.lower() for s in _as_list(expected)}
    if key == "tenant":
        return facts.tenant in set(_as_list(expected))
    if key == "tactic":
        return bool(set(_as_list(expected)) & set(facts.tactics))
    if key == "technique":
        return _any_glob(_as_list(expected), facts.techniques)
    if key == "rule_id":
        return _any_glob(_as_list(expected), facts.rule_ids)
    if key == "principal":
        return _any_glob(_as_list(expected), [facts.principal or ""])
    if key == "hostname":
        return _any_glob(_as_list(expected), facts.hostnames)
    if key == "source_ip":
        return _any_glob(_as_list(expected), facts.source_ips)
    # Unreachable: the loader rejects unknown keys.
    raise RoutingError("unsupported match key %r" % key)


def parse_rule(document: Dict[str, Any], source_path: Optional[str] = None) -> RoutingRule:
    if not isinstance(document, dict):
        raise RoutingError("%s: a routing rule must be a mapping" % (source_path or "<inline>"))

    where = source_path or document.get("id") or "<inline>"
    rule_id = document.get("id")
    if not rule_id:
        raise RoutingError("%s: routing rule needs an id" % where)
    team = document.get("team")
    if not team:
        raise RoutingError("%s: routing rule %r needs a team" % (where, rule_id))

    match = document.get("match") or {}
    if not isinstance(match, dict):
        raise RoutingError("%s: %r match must be a mapping" % (where, rule_id))
    unknown = set(match) - MATCH_KEYS
    if unknown:
        raise RoutingError(
            "%s: %r matches on unknown field(s) %s (expected any of %s)"
            % (where, rule_id, ", ".join(sorted(unknown)), ", ".join(sorted(MATCH_KEYS)))
        )
    for bound in ("min_risk", "max_risk"):
        if bound in match:
            try:
                value = int(match[bound])
            except (TypeError, ValueError) as exc:
                raise RoutingError("%s: %r %s must be a number" % (where, rule_id, bound)) from exc
            if not 0 <= value <= 100:
                raise RoutingError("%s: %r %s must be 0-100" % (where, rule_id, bound))
    if (
        "min_risk" in match
        and "max_risk" in match
        and int(match["min_risk"]) > int(match["max_risk"])
    ):
        raise RoutingError("%s: %r has min_risk above max_risk" % (where, rule_id))

    try:
        priority = int(document.get("priority", 100))
    except (TypeError, ValueError) as exc:
        raise RoutingError("%s: %r priority must be a number" % (where, rule_id)) from exc

    return RoutingRule(
        id=str(rule_id),
        team=str(team),
        priority=priority,
        title=document.get("title"),
        description=document.get("description"),
        enabled=bool(document.get("enabled", True)),
        match=dict(match),
        source_path=source_path,
    )


def load_routing_table(path: Any, *, strict: bool = False) -> RoutingTable:
    """Load every ``*.yml`` under ``path``.

    Collects errors rather than raising by default: one malformed file should
    not leave a running deployment with no routing at all. ``strict=True`` is
    for the linter, which does want the exception.
    """
    directory = Path(path)
    rules: List[RoutingRule] = []
    errors: List[str] = []
    seen: Dict[str, str] = {}

    if not directory.exists():
        return RoutingTable(rules=[], errors=[])

    for file_path in sorted(directory.rglob("*.yml")) + sorted(directory.rglob("*.yaml")):
        try:
            documents = [
                doc for doc in yaml.safe_load_all(file_path.read_text(encoding="utf-8")) if doc
            ]
        except yaml.YAMLError as exc:
            message = "%s: not valid YAML (%s)" % (file_path, exc)
            if strict:
                raise RoutingError(message) from exc
            errors.append(message)
            continue

        for document in documents:
            try:
                rule = parse_rule(document, source_path=str(file_path))
            except RoutingError as exc:
                if strict:
                    raise
                errors.append(str(exc))
                continue
            if rule.id in seen:
                message = "%s: duplicate routing rule id %r (also in %s)" % (
                    file_path,
                    rule.id,
                    seen[rule.id],
                )
                if strict:
                    raise RoutingError(message)
                errors.append(message)
                continue
            seen[rule.id] = str(file_path)
            rules.append(rule)

    table = RoutingTable(rules=rules, errors=errors)
    logger.info(
        "loaded routing table",
        extra={"rules": len(table.rules), "errors": len(table.errors)},
    )
    return table
