"""Detection engine: normalized events in, scored alerts out.

Per event the engine

1. flattens it once and asks the rule set for the rules whose logsource can
   match (indexed by OCSF ``class_uid``, so most rules are never evaluated);
2. evaluates each candidate with the streaming Sigma evaluator;
3. for aggregation rules (``| count() by user >= 5``) feeds a sliding window
   keyed by the group-by value and only fires when the threshold is crossed
   inside the rule's ``timeframe``;
4. scores the match (severity x confidence x asset criticality x context),
   attaches ATT&CK mapping and evidence, and
5. deduplicates and suppresses: the same rule and entity within the dedup
   window becomes one alert with an occurrence count, and context that says
   "this is a load-test account" suppresses instead of paging someone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..assets import AssetInventory, get_inventory
from ..config import Settings, get_settings
from ..correlate.risk import build_context, score_alert, severity_for_level
from ..models.alert import Alert, AlertStatus, DetectionMatch
from ..models.ocsf import OcsfEvent, flatten_event
from ..sigma.evaluator import MatchResult, evaluate_flat
from ..sigma.loader import RuleSet
from ..sigma.pipeline import resolve_field
from ..sigma.rule import SigmaRule
from .state import SuppressionCache, WindowEntry, WindowStore

log = logging.getLogger("signalforge.detect")

#: Called with an indicator value, returns a verdict string (or None).
IntelLookup = Callable[[str], Optional[str]]


@dataclass
class EngineStats:
    events_processed: int = 0
    events_deduped: int = 0
    rules_evaluated: int = 0
    matches: int = 0
    alerts_emitted: int = 0
    alerts_deduped: int = 0
    alerts_suppressed: int = 0
    windows_open: int = 0
    detection_latency_ms_total: float = 0.0

    @property
    def mean_latency_ms(self) -> float:
        if not self.events_processed:
            return 0.0
        return self.detection_latency_ms_total / self.events_processed

    def to_dict(self) -> Dict[str, Any]:
        return {**self.__dict__, "mean_latency_ms": round(self.mean_latency_ms, 3)}


class DetectionEngine:
    def __init__(
        self,
        ruleset: RuleSet,
        *,
        settings: Optional[Settings] = None,
        inventory: Optional[AssetInventory] = None,
        intel_lookup: Optional[IntelLookup] = None,
    ) -> None:
        self.ruleset = ruleset
        self.settings = settings or get_settings()
        self.inventory = inventory or get_inventory()
        self.intel_lookup = intel_lookup
        self.windows = WindowStore()
        self.suppression = SuppressionCache(self.settings.alert_dedup_window_seconds)
        #: Content hashes of events already evaluated.  The bus is at-least-once,
        #: so without this a re-delivered batch would inflate every count-based
        #: detection.
        self.seen_events = SuppressionCache(3600)
        self.stats = EngineStats()
        #: dedup_key -> live alert, so repeats become occurrences.
        self._open_alerts: Dict[str, Alert] = {}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def process(self, event: OcsfEvent, *, now: Optional[datetime] = None) -> List[Alert]:
        """Evaluate every candidate rule against one event."""
        import time as _time

        started = _time.perf_counter()
        reference = now or event.time
        dedup_key = event.sf_dedup_key or event.compute_dedup_key()
        if self.seen_events.seen(("event", event.sf_tenant, dedup_key), reference):
            self.stats.events_deduped += 1
            return []

        flat = flatten_event(event)
        alerts: List[Alert] = []

        for rule in self.ruleset.candidates_for(event):
            self.stats.rules_evaluated += 1
            result = evaluate_flat(rule, flat)
            if not result.matched:
                continue
            self.stats.matches += 1
            if rule.is_stateful:
                alert = self._handle_stateful(rule, event, flat, result, reference)
            else:
                alert = self._build_alert(rule, event, flat, result, reference)
            if alert is not None:
                alerts.append(alert)

        self.stats.events_processed += 1
        self.stats.windows_open = self.windows.size
        self.stats.detection_latency_ms_total += (_time.perf_counter() - started) * 1000
        return alerts

    def process_many(self, events: Sequence[OcsfEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        for event in events:
            alerts.extend(self.process(event))
        return alerts

    def sweep(self, now: Optional[datetime] = None) -> int:
        """Drop expired window state; call periodically from the worker loop."""
        return self.windows.sweep(now)

    # ------------------------------------------------------------------ #
    # Stateful (aggregation) rules
    # ------------------------------------------------------------------ #
    def _handle_stateful(
        self,
        rule: SigmaRule,
        event: OcsfEvent,
        flat: Dict[str, Any],
        result: MatchResult,
        now: datetime,
    ) -> Optional[Alert]:
        aggregation = rule.condition.aggregation
        assert aggregation is not None
        timespan = rule.timeframe or self.settings.correlation_window_seconds

        group_field = resolve_field(aggregation.group_by) if aggregation.group_by else None
        group_value = _first(flat.get(group_field)) if group_field else "*"
        if group_field and group_value is None:
            # Nothing to group by - the rule cannot make a statement about it.
            return None

        value_field = resolve_field(aggregation.field) if aggregation.field else None
        window = self.windows.window((rule.id, event.sf_tenant, group_value), timespan)
        window.add(
            WindowEntry(
                time=event.time,
                ref=event.sf_event_id,
                value=_first(flat.get(value_field)) if value_field else None,
                label=rule.id,
                payload=event,
            )
        )

        observed = window.distinct(now) if value_field else window.count(now)
        if not aggregation.compare(observed):
            return None

        # Threshold crossed: fire once per window unless the rule opts out.
        suppress_ttl = rule.hints.suppress_seconds or timespan
        suppression_key = ("stateful", rule.id, event.sf_tenant, group_value)
        if self.suppression.seen(suppression_key, now, suppress_ttl):
            self.stats.alerts_deduped += 1
            return None

        entries = window.entries(now)
        detection = DetectionMatch(
            condition=rule.condition.source,
            matched_selections=result.matched_selections,
            matched_fields=result.matched_fields,
            event_count=int(observed),
            timeframe_seconds=timespan,
        )
        return self._build_alert(
            rule,
            event,
            flat,
            result,
            now,
            detection=detection,
            event_ids=[entry.ref for entry in entries],
            first_seen=entries[0].time if entries else event.time,
        )

    # ------------------------------------------------------------------ #
    # Alert construction
    # ------------------------------------------------------------------ #
    def _build_alert(
        self,
        rule: SigmaRule,
        event: OcsfEvent,
        flat: Dict[str, Any],
        result: MatchResult,
        now: datetime,
        *,
        detection: Optional[DetectionMatch] = None,
        event_ids: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
    ) -> Optional[Alert]:
        principal = event.principal
        target = event.target_principal
        intel_verdict = None
        if self.intel_lookup and event.source_ip:
            try:
                intel_verdict = self.intel_lookup(event.source_ip)
            except Exception as exc:  # enrichment must never break detection
                log.warning("intel lookup failed", extra={"error": str(exc)})

        context = build_context(
            event,
            inventory=self.inventory,
            internal_networks=self.settings.internal_networks,
            intel_verdict=intel_verdict,
            now=now,
        )
        # A rule may assert extra context signals itself (e.g. a cloud rule that
        # knows its target is privileged).  Only known signal names are honoured.
        for signal in rule.hints.context_modifiers:
            context.add(signal)

        criticality = self.inventory.criticality_score(
            hostname=event.hostname,
            user=target or principal,
            resource=event.resources[0].name if event.resources else None,
        )
        assessment = score_alert(
            severity=severity_for_level(rule.level),
            confidence=rule.hints.confidence,
            asset_criticality=criticality,
            context=context,
        )

        alert = Alert(
            tenant=event.sf_tenant,
            rule_id=rule.id,
            rule_title=rule.title,
            rule_level=rule.level,
            rule_path=rule.source_path,
            rule_author=rule.author,
            description=rule.description,
            falsepositives=rule.falsepositives,
            references=rule.references,
            severity=severity_for_level(rule.level),
            confidence=rule.hints.confidence,
            asset_criticality=criticality,
            context_modifier=context.modifier,
            risk_score=assessment.score,
            risk_level=assessment.level,
            risk_factors=assessment.factors,
            tactics=rule.tactics,
            techniques=rule.techniques,
            principal=principal,
            target_principal=target,
            source_ip=event.source_ip,
            hostname=event.hostname,
            session_uid=event.session_uid,
            resources=[r.name for r in event.resources if r.name],
            detection=detection
            or DetectionMatch(
                condition=rule.condition.source,
                matched_selections=result.matched_selections,
                matched_fields=result.matched_fields,
            ),
            event_ids=event_ids or [event.sf_event_id],
            sample_event=event.to_document(),
            first_seen=first_seen or event.time,
            last_seen=event.time,
            is_building_block=bool(rule.hints.tuning.get("building_block", False)),
        )
        if rule.hints.dedup_by:
            alert.dedup_key = _custom_dedup_key(alert, flat, rule.hints.dedup_by)

        # Benign-by-context: record the alert as suppressed instead of paging.
        if context.suppressing and rule.hints.tuning.get("suppress_benign_context", True):
            alert.status = AlertStatus.SUPPRESSED
            alert.suppressed_reason = "; ".join(context.describe())
            self.stats.alerts_suppressed += 1
            log.info(
                "alert suppressed", extra={"rule_id": rule.id, "reason": alert.suppressed_reason}
            )
            return None

        existing = self._open_alerts.get(alert.dedup_key)
        if existing is not None and (
            (alert.last_seen - existing.last_seen).total_seconds()
            < self.settings.alert_dedup_window_seconds
        ):
            existing.occurrences += 1
            existing.last_seen = max(existing.last_seen, alert.last_seen)
            for event_id in alert.event_ids:
                if event_id not in existing.event_ids:
                    existing.event_ids.append(event_id)
            if alert.risk_score > existing.risk_score:
                existing.risk_score = alert.risk_score
                existing.risk_level = alert.risk_level
            self.stats.alerts_deduped += 1
            return None

        self._open_alerts[alert.dedup_key] = alert
        self.stats.alerts_emitted += 1
        log.info(
            "alert",
            extra={
                "rule_id": rule.id,
                "risk": alert.risk_score,
                "principal": principal,
                "tenant": alert.tenant,
            },
        )
        return alert

    # ------------------------------------------------------------------ #
    def open_alert(self, dedup_key: str) -> Optional[Alert]:
        return self._open_alerts.get(dedup_key)

    def reset(self) -> None:
        self.windows.clear()
        self.suppression.clear()
        self.seen_events.clear()
        self._open_alerts.clear()
        self.stats = EngineStats()


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _custom_dedup_key(alert: Alert, flat: Dict[str, Any], fields: Sequence[str]) -> str:
    import hashlib

    parts = [alert.tenant, alert.rule_id]
    for field_name in fields:
        parts.append(str(_first(flat.get(resolve_field(field_name)))))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]
