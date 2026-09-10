"""Sigma rule and correlation-rule models.

Parses the Sigma specification subset SignalForge needs: rule metadata, the
``logsource``/``detection`` blocks (including ``timeframe``), condition
expressions, ATT&CK tags, and Sigma v2 ``correlation`` rules
(``event_count``, ``value_count``, ``temporal``, ``temporal_ordered``).

A rule may also carry a ``signalforge:`` block with platform-specific hints
(detection confidence, dedup keys, suggested response playbook).  Those are
extensions, not Sigma - the loader keeps them namespaced so the rule stays
valid for any other Sigma consumer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .condition import ParsedCondition, parse_condition
from .errors import SigmaParseError
from .matching import FieldMatcher, KeywordMatcher

Matcher = Union[FieldMatcher, KeywordMatcher]

VALID_LEVELS = ("informational", "low", "medium", "high", "critical")
VALID_STATUS = ("stable", "test", "experimental", "deprecated", "unsupported")
CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")

_TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

_ATTACK_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}


def parse_timespan(value: Any) -> Optional[int]:
    """``"15m"`` -> 900 seconds.  Bare numbers are treated as seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    match = _TIMESPAN_RE.match(str(value).strip())
    if not match:
        raise SigmaParseError("invalid timespan %r (expected e.g. 30s, 15m, 2h, 7d)" % value)
    return int(match.group(1)) * _TIMESPAN_UNITS[match.group(2).lower()]


def tactics_from_tags(tags: Sequence[str]) -> List[str]:
    """``attack.credential_access`` -> ``credential_access``."""
    out = []
    for tag in tags:
        if tag.lower().startswith("attack."):
            value = tag.split(".", 1)[1].lower()
            if value in _ATTACK_TACTICS and value not in out:
                out.append(value)
    return out


def techniques_from_tags(tags: Sequence[str]) -> List[str]:
    """``attack.t1110.001`` -> ``T1110.001``."""
    out = []
    for tag in tags:
        lowered = tag.lower()
        if lowered.startswith("attack.t"):
            technique = lowered.split(".", 1)[1].upper()
            if technique not in out:
                out.append(technique)
    return out


@dataclass(frozen=True)
class LogSource:
    category: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    definition: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "LogSource":
        data = data or {}
        unknown = set(data) - {"category", "product", "service", "definition"}
        if unknown:
            raise SigmaParseError("unsupported logsource key(s): %s" % ", ".join(sorted(unknown)))
        return cls(
            category=_lower(data.get("category")),
            product=_lower(data.get("product")),
            service=_lower(data.get("service")),
            definition=data.get("definition"),
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            key: value
            for key, value in (
                ("category", self.category), ("product", self.product),
                ("service", self.service), ("definition", self.definition),
            )
            if value
        }


@dataclass
class Search:
    """One named search identifier from the ``detection`` block.

    ``groups`` is a disjunction of conjunctions: the outer list is OR (a YAML
    list of maps), the inner list is AND (the keys of one map).
    """

    name: str
    groups: List[List[Matcher]] = field(default_factory=list)

    @classmethod
    def from_definition(cls, name: str, definition: Any) -> "Search":
        groups: List[List[Matcher]] = []

        def _from_map(mapping: Dict[str, Any]) -> List[Matcher]:
            if not mapping:
                raise SigmaParseError("search %r contains an empty map" % name)
            return [FieldMatcher.compile(str(key), value) for key, value in mapping.items()]

        if isinstance(definition, dict):
            groups.append(_from_map(definition))
        elif isinstance(definition, list):
            keywords: List[Any] = []
            for item in definition:
                if isinstance(item, dict):
                    groups.append(_from_map(item))
                else:
                    keywords.append(item)
            if keywords:
                groups.append([KeywordMatcher(values=tuple(keywords))])
        elif isinstance(definition, (str, int, float, bool)):
            groups.append([KeywordMatcher(values=(definition,))])
        else:
            raise SigmaParseError("unsupported definition for search %r" % name)
        if not groups:
            raise SigmaParseError("search %r has no conditions" % name)
        return cls(name=name, groups=groups)

    @property
    def fields(self) -> List[str]:
        return sorted({m.field for group in self.groups for m in group})

    def match(self, flat: Dict[str, Any]) -> bool:
        return any(all(matcher.match(flat) for matcher in group) for group in self.groups)

    def matched_fields(self, flat: Dict[str, Any]) -> Dict[str, Any]:
        """The event values that made this search match (alert evidence)."""
        evidence: Dict[str, Any] = {}
        for group in self.groups:
            if all(matcher.match(flat) for matcher in group):
                for matcher in group:
                    if matcher.field in flat:
                        evidence[matcher.field] = flat[matcher.field]
                break
        return evidence


@dataclass
class SignalForgeHints:
    """The optional, namespaced ``signalforge:`` block of a rule."""

    confidence: int = 7
    dedup_by: Tuple[str, ...] = ()
    response_playbook: Optional[str] = None
    context_modifiers: Dict[str, float] = field(default_factory=dict)
    suppress_seconds: Optional[int] = None
    correlation_scenario: Optional[str] = None
    tuning: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "SignalForgeHints":
        data = data or {}
        confidence = data.get("confidence", 7)
        if not isinstance(confidence, int) or not 1 <= confidence <= 10:
            raise SigmaParseError("signalforge.confidence must be an integer 1-10")
        return cls(
            confidence=confidence,
            dedup_by=tuple(data.get("dedup_by") or ()),
            response_playbook=data.get("response_playbook"),
            context_modifiers={k: float(v) for k, v in (data.get("context_modifiers") or {}).items()},
            suppress_seconds=parse_timespan(data.get("suppress")),
            correlation_scenario=data.get("scenario"),
            tuning=dict(data.get("tuning") or {}),
        )


@dataclass
class SigmaRule:
    """A single Sigma detection rule."""

    id: str
    title: str
    logsource: LogSource
    searches: Dict[str, Search]
    condition: ParsedCondition
    level: str = "medium"
    status: str = "experimental"
    description: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    modified: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    timeframe: Optional[int] = None
    related: List[Dict[str, str]] = field(default_factory=list)
    name: Optional[str] = None  # referenced by correlation rules
    hints: SignalForgeHints = field(default_factory=SignalForgeHints)
    source_path: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    # -- ATT&CK ------------------------------------------------------------
    @property
    def tactics(self) -> List[str]:
        return tactics_from_tags(self.tags)

    @property
    def techniques(self) -> List[str]:
        return techniques_from_tags(self.tags)

    @property
    def is_stateful(self) -> bool:
        return self.condition.is_stateful

    @property
    def reference_names(self) -> List[str]:
        return [n for n in (self.name, self.id) if n]

    def matches_logsource(self, event_logsource: Dict[str, Optional[str]]) -> bool:
        for key, expected in self.logsource.as_dict().items():
            if key == "definition":
                continue
            observed = event_logsource.get(key)
            if expected and (observed or "").lower() != expected:
                return False
        return True

    # -- parsing -----------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_path: Optional[str] = None) -> "SigmaRule":
        if not isinstance(data, dict):
            raise SigmaParseError("rule must be a YAML mapping", source_path)
        for required in ("title", "detection"):
            if not data.get(required):
                raise SigmaParseError("missing required field %r" % required, source_path)

        detection = data.get("detection")
        if not isinstance(detection, dict):
            raise SigmaParseError("detection block must be a mapping", source_path)
        condition_expr = detection.get("condition")
        if condition_expr is None:
            raise SigmaParseError("detection block requires a condition", source_path)
        if isinstance(condition_expr, list):
            # Sigma allows a list of conditions, meaning OR.
            condition_expr = " or ".join("(%s)" % item for item in condition_expr)

        searches: Dict[str, Search] = {}
        for key, value in detection.items():
            if key in {"condition", "timeframe"}:
                continue
            searches[key] = Search.from_definition(key, value)
        if not searches:
            raise SigmaParseError("detection block defines no search identifiers", source_path)

        parsed_condition = parse_condition(str(condition_expr), list(searches))

        level = str(data.get("level", "medium")).lower()
        if level not in VALID_LEVELS:
            raise SigmaParseError(
                "invalid level %r (expected one of %s)" % (level, ", ".join(VALID_LEVELS)),
                source_path,
            )
        status = str(data.get("status", "experimental")).lower()
        if status not in VALID_STATUS:
            raise SigmaParseError("invalid status %r" % status, source_path)

        rule_id = str(data.get("id") or "").strip()
        if not rule_id:
            raise SigmaParseError("rule requires a stable id", source_path)

        return cls(
            id=rule_id,
            title=str(data["title"]),
            logsource=LogSource.from_dict(data.get("logsource")),
            searches=searches,
            condition=parsed_condition,
            level=level,
            status=status,
            description=data.get("description"),
            author=data.get("author"),
            date=str(data["date"]) if data.get("date") else None,
            modified=str(data["modified"]) if data.get("modified") else None,
            references=list(data.get("references") or []),
            tags=[str(tag) for tag in (data.get("tags") or [])],
            fields=list(data.get("fields") or []),
            falsepositives=[str(fp) for fp in (data.get("falsepositives") or [])],
            timeframe=parse_timespan(detection.get("timeframe")),
            related=list(data.get("related") or []),
            name=data.get("name"),
            hints=SignalForgeHints.from_dict(data.get("signalforge")),
            source_path=source_path,
            raw=data,
        )


@dataclass
class SigmaCorrelationRule:
    """A Sigma v2 correlation rule.

    Example::

        correlation:
          type: temporal_ordered
          rules: [auth_failures, auth_success, privilege_grant]
          group-by: [actor.user.name]
          timespan: 15m
    """

    id: str
    title: str
    type: str
    rule_refs: List[str]
    group_by: List[str]
    timespan: int
    level: str = "high"
    status: str = "experimental"
    description: Optional[str] = None
    condition: Dict[str, Any] = field(default_factory=dict)
    aliases: Dict[str, Dict[str, str]] = field(default_factory=dict)
    generate: bool = False
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    name: Optional[str] = None
    hints: SignalForgeHints = field(default_factory=SignalForgeHints)
    source_path: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def tactics(self) -> List[str]:
        return tactics_from_tags(self.tags)

    @property
    def techniques(self) -> List[str]:
        return techniques_from_tags(self.tags)

    @property
    def is_ordered(self) -> bool:
        return self.type == "temporal_ordered"

    @property
    def threshold(self) -> Optional[float]:
        for key in ("gte", "gt", "lte", "lt", "eq"):
            if key in self.condition:
                return float(self.condition[key])
        return None

    def compare(self, value: float) -> bool:
        if "gte" in self.condition:
            return value >= float(self.condition["gte"])
        if "gt" in self.condition:
            return value > float(self.condition["gt"])
        if "lte" in self.condition:
            return value <= float(self.condition["lte"])
        if "lt" in self.condition:
            return value < float(self.condition["lt"])
        if "eq" in self.condition:
            return value == float(self.condition["eq"])
        return value >= 1

    @property
    def value_field(self) -> Optional[str]:
        return self.condition.get("field")

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_path: Optional[str] = None) -> "SigmaCorrelationRule":
        correlation = data.get("correlation")
        if not isinstance(correlation, dict):
            raise SigmaParseError("correlation block must be a mapping", source_path)
        corr_type = str(correlation.get("type") or "").lower()
        if corr_type not in CORRELATION_TYPES:
            raise SigmaParseError(
                "invalid correlation type %r (expected one of %s)"
                % (corr_type, ", ".join(CORRELATION_TYPES)),
                source_path,
            )
        refs = correlation.get("rules") or correlation.get("rule") or []
        if isinstance(refs, str):
            refs = [refs]
        if not refs:
            raise SigmaParseError("correlation rule references no rules", source_path)

        group_by = correlation.get("group-by") or correlation.get("group_by") or []
        if isinstance(group_by, str):
            group_by = [group_by]
        timespan = parse_timespan(correlation.get("timespan"))
        if not timespan:
            raise SigmaParseError("correlation rule requires a timespan", source_path)

        condition = correlation.get("condition") or {}
        if corr_type in {"event_count", "value_count"} and not condition:
            raise SigmaParseError(
                "%s correlation requires a condition (e.g. {gte: 10})" % corr_type, source_path
            )
        if corr_type == "value_count" and not condition.get("field"):
            raise SigmaParseError("value_count correlation requires condition.field", source_path)
        if corr_type in {"temporal", "temporal_ordered"} and len(refs) < 2:
            raise SigmaParseError("%s correlation needs at least two rules" % corr_type, source_path)

        rule_id = str(data.get("id") or "").strip()
        if not rule_id:
            raise SigmaParseError("correlation rule requires a stable id", source_path)
        level = str(data.get("level", "high")).lower()
        if level not in VALID_LEVELS:
            raise SigmaParseError("invalid level %r" % level, source_path)

        return cls(
            id=rule_id,
            title=str(data.get("title") or rule_id),
            type=corr_type,
            rule_refs=[str(ref) for ref in refs],
            group_by=[str(field_name) for field_name in group_by],
            timespan=timespan,
            level=level,
            status=str(data.get("status", "experimental")).lower(),
            description=data.get("description"),
            condition=dict(condition),
            aliases=dict(correlation.get("aliases") or {}),
            generate=bool(correlation.get("generate", False)),
            tags=[str(tag) for tag in (data.get("tags") or [])],
            falsepositives=[str(fp) for fp in (data.get("falsepositives") or [])],
            name=data.get("name"),
            hints=SignalForgeHints.from_dict(data.get("signalforge")),
            source_path=source_path,
            raw=data,
        )


def parse_rule_document(
    data: Dict[str, Any], source_path: Optional[str] = None
) -> Union[SigmaRule, SigmaCorrelationRule]:
    """Parse one YAML document into a detection or correlation rule."""
    if not isinstance(data, dict):
        raise SigmaParseError("rule document must be a mapping", source_path)
    if "correlation" in data:
        return SigmaCorrelationRule.from_dict(data, source_path)
    return SigmaRule.from_dict(data, source_path)


def _lower(value: Any) -> Optional[str]:
    return str(value).lower() if value is not None else None
