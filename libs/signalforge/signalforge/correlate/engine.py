"""Correlation engine: individual alerts in, scenario hits out.

Implements the four Sigma v2 correlation types over alert streams:

``event_count``     N alerts from the referenced rule(s) for one group key
``value_count``     N *distinct* values of a field for one group key
``temporal``        every referenced rule fired within the timespan, any order
``temporal_ordered`` every referenced rule fired within the timespan, in order

Grouping uses the correlation rule's ``group-by`` fields resolved against the
alert (``actor.user.name`` -> the alert's principal, ``src_endpoint.ip`` -> its
source IP), which is what makes "same user, same IP, same host" chains hold
together across sources.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..detect.state import SuppressionCache, WindowEntry, WindowStore
from ..models.alert import Alert
from ..sigma.loader import RuleSet
from ..sigma.rule import SigmaCorrelationRule

log = logging.getLogger("signalforge.correlate")

#: Correlation ``group-by`` field -> attribute on the alert.
GROUP_FIELD_ACCESSORS: Dict[str, str] = {
    "actor.user.name": "principal",
    "actor.user.email_addr": "principal",
    "user.name": "target_principal",
    "user.email_addr": "target_principal",
    "principal": "principal",
    "src_endpoint.ip": "source_ip",
    "source_ip": "source_ip",
    "device.hostname": "hostname",
    "hostname": "hostname",
    "actor.session.uid": "session_uid",
    "session_uid": "session_uid",
    "sf_tenant": "tenant",
    "tenant": "tenant",
}


def group_value(alert: Alert, field_name: str) -> Optional[str]:
    """Resolve one ``group-by`` field against an alert."""
    attribute = GROUP_FIELD_ACCESSORS.get(field_name)
    if attribute:
        return getattr(alert, attribute, None)
    # Fall back to the alert's evidence, then to the sample event document.
    evidence = alert.detection.matched_fields or {}
    if field_name in evidence:
        value = evidence[field_name]
        return str(value[0] if isinstance(value, list) else value)
    document = alert.sample_event or {}
    cursor: Any = document
    for part in field_name.split("."):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        else:
            return None
    if isinstance(cursor, (str, int, float)):
        return str(cursor)
    return None


@dataclass
class CorrelationHit:
    """A correlation rule that has just been satisfied."""

    correlation: SigmaCorrelationRule
    group_key: Tuple[str, ...]
    alerts: List[Alert]
    first_seen: datetime
    last_seen: datetime
    observed: float = 0.0
    sequence: List[str] = field(default_factory=list)
    complete: bool = True

    @property
    def scenario(self) -> str:
        return self.correlation.hints.correlation_scenario or self.correlation.id

    @property
    def tactics(self) -> List[str]:
        merged: List[str] = list(self.correlation.tactics)
        for alert in self.alerts:
            for tactic in alert.tactics:
                if tactic not in merged:
                    merged.append(tactic)
        return merged

    @property
    def techniques(self) -> List[str]:
        merged: List[str] = list(self.correlation.techniques)
        for alert in self.alerts:
            for technique in alert.techniques:
                if technique not in merged:
                    merged.append(technique)
        return merged

    @property
    def dedup_key(self) -> str:
        import hashlib

        parts = [
            self.alerts[0].tenant if self.alerts else "default",
            self.correlation.id,
            *self.group_key,
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]

    def describe(self) -> str:
        return "%s (%s)" % (self.correlation.title, " / ".join(self.group_key) or "global")


@dataclass
class CorrelationStats:
    alerts_processed: int = 0
    hits: int = 0
    suppressed: int = 0
    windows_open: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class CorrelationEngine:
    def __init__(
        self,
        ruleset: RuleSet,
        *,
        suppression_seconds: int = 900,
    ) -> None:
        self.ruleset = ruleset
        self.windows = WindowStore()
        self.suppression = SuppressionCache(suppression_seconds)
        self.stats = CorrelationStats()

    # ------------------------------------------------------------------ #
    def process(self, alert: Alert, *, now: Optional[datetime] = None) -> List[CorrelationHit]:
        """Feed one alert into every correlation rule that references its rule."""
        self.stats.alerts_processed += 1
        reference = now or alert.last_seen
        hits: List[CorrelationHit] = []

        for correlation in self.ruleset.correlations_referencing(alert.rule_id):
            key = self._group_key(correlation, alert)
            if key is None:
                continue
            window = self.windows.window((correlation.id, alert.tenant, *key), correlation.timespan)
            window.add(
                WindowEntry(
                    time=alert.last_seen,
                    ref=alert.alert_id,
                    value=self._value_for(correlation, alert),
                    label=alert.rule_id,
                    payload=alert,
                )
            )
            hit = self._evaluate(correlation, key, window, reference)
            if hit is None:
                continue
            if self.suppression.seen(
                ("correlation", correlation.id, alert.tenant, *key),
                reference,
                correlation.timespan,
            ):
                self.stats.suppressed += 1
                continue
            self.stats.hits += 1
            hits.append(hit)
            log.info(
                "correlation hit",
                extra={
                    "correlation_id": correlation.id,
                    "group": key,
                    "alerts": len(hit.alerts),
                    "scenario": hit.scenario,
                },
            )
        self.stats.windows_open = self.windows.size
        return hits

    def process_many(self, alerts: Sequence[Alert]) -> List[CorrelationHit]:
        hits: List[CorrelationHit] = []
        for alert in alerts:
            hits.extend(self.process(alert))
        return hits

    def sweep(self, now: Optional[datetime] = None) -> int:
        return self.windows.sweep(now)

    def reset(self) -> None:
        self.windows.clear()
        self.suppression.clear()
        self.stats = CorrelationStats()

    # ------------------------------------------------------------------ #
    def _group_key(
        self, correlation: SigmaCorrelationRule, alert: Alert
    ) -> Optional[Tuple[str, ...]]:
        if not correlation.group_by:
            return ()
        values: List[str] = []
        for field_name in correlation.group_by:
            value = group_value(alert, field_name)
            if value is None:
                # Cannot place this alert in a group - skip rather than guess.
                return None
            values.append(str(value).lower())
        return tuple(values)

    @staticmethod
    def _value_for(correlation: SigmaCorrelationRule, alert: Alert) -> Optional[str]:
        if correlation.type != "value_count" or not correlation.value_field:
            return None
        return group_value(alert, correlation.value_field)

    def _evaluate(
        self,
        correlation: SigmaCorrelationRule,
        key: Tuple[str, ...],
        window: Any,
        now: datetime,
    ) -> Optional[CorrelationHit]:
        entries = window.entries(now)
        if not entries:
            return None
        alerts = [entry.payload for entry in entries if isinstance(entry.payload, Alert)]
        if not alerts:
            return None

        expected_ids = [self.ruleset.rule_id_for(ref) or ref for ref in correlation.rule_refs]

        if correlation.type == "event_count":
            observed = float(len(entries))
            if not correlation.compare(observed):
                return None
            return self._hit(correlation, key, alerts, entries, observed)

        if correlation.type == "value_count":
            observed = float(window.distinct(now))
            if not correlation.compare(observed):
                return None
            return self._hit(correlation, key, alerts, entries, observed)

        observed_labels = [entry.label for entry in entries if entry.label]
        if correlation.type == "temporal":
            if not set(expected_ids).issubset(set(observed_labels)):
                return None
            return self._hit(correlation, key, alerts, entries, float(len(set(observed_labels))))

        if correlation.type == "temporal_ordered":
            if not _is_ordered_subsequence(expected_ids, observed_labels):
                return None
            return self._hit(correlation, key, alerts, entries, float(len(expected_ids)))

        return None

    @staticmethod
    def _hit(
        correlation: SigmaCorrelationRule,
        key: Tuple[str, ...],
        alerts: List[Alert],
        entries: Sequence[Any],
        observed: float,
    ) -> CorrelationHit:
        return CorrelationHit(
            correlation=correlation,
            group_key=key,
            alerts=alerts,
            first_seen=entries[0].time,
            last_seen=entries[-1].time,
            observed=observed,
            sequence=[entry.label for entry in entries if entry.label],
            complete=True,
        )


def _is_ordered_subsequence(expected: Sequence[str], observed: Sequence[str]) -> bool:
    """True when every expected rule appears in order within ``observed``.

    Extra alerts in between are fine - real intrusions are noisy - but the
    declared stages must occur in the declared order.
    """
    cursor = 0
    for label in observed:
        if cursor < len(expected) and label == expected[cursor]:
            cursor += 1
    return cursor == len(expected)
