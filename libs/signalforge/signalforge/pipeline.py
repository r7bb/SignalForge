"""The full detection pipeline, in one object.

``raw records -> OCSF -> event store -> detections -> enrichment ->
correlation -> incidents``

The streaming services (``services/normalizer``, ``services/detector``,
``services/correlator``) each own one hop of this and pass work over the bus;
this class runs the whole chain in-process, which is what the integration
tests, the load harness and the ``/pipeline/simulate`` endpoint use.  Keeping
one implementation of the wiring means the tested path and the deployed path
cannot drift apart.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import Settings, get_settings
from .correlate.engine import CorrelationEngine, CorrelationHit
from .detect.engine import DetectionEngine
from .enrich.intel import ThreatIntelService
from .incidents.manager import IncidentManager
from .models.alert import Alert
from .models.incident import Incident
from .models.ocsf import OcsfEvent, RawLogRecord
from .normalize import registry
from .sigma.loader import RuleSet
from .storage.events import EventStore, IndexResult

log = logging.getLogger("signalforge.pipeline")


@dataclass
class PipelineResult:
    events: List[OcsfEvent] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    hits: List[CorrelationHit] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    dlq: List[Tuple[RawLogRecord, str]] = field(default_factory=list)
    index_result: Optional[IndexResult] = None
    duration_ms: float = 0.0

    @property
    def counts(self) -> Dict[str, Any]:
        return {
            "events": len(self.events),
            "alerts": len(self.alerts),
            "correlations": len(self.hits),
            "incidents": len(self.incidents),
            "dlq": len(self.dlq),
            "indexed": self.index_result.indexed if self.index_result else 0,
            "duplicates": self.index_result.duplicates if self.index_result else 0,
            "duration_ms": round(self.duration_ms, 2),
        }

    def incident_keys(self) -> List[str]:
        return [incident.key for incident in self.incidents]


class Pipeline:
    def __init__(
        self,
        ruleset: RuleSet,
        event_store: EventStore,
        *,
        settings: Optional[Settings] = None,
        session_factory: Any = None,
        intel: Optional[ThreatIntelService] = None,
        engine: Optional[DetectionEngine] = None,
        correlator: Optional[CorrelationEngine] = None,
        incidents: Optional[IncidentManager] = None,
        enrich_events: bool = False,
    ) -> None:
        self.settings = settings or get_settings()
        self.ruleset = ruleset
        self.event_store = event_store
        self.intel = intel
        self.enrich_events = enrich_events
        self.engine = engine or DetectionEngine(
            ruleset,
            settings=self.settings,
            intel_lookup=(intel.verdict if intel else None),
        )
        self.correlator = correlator or CorrelationEngine(
            ruleset, suppression_seconds=self.settings.correlation_window_seconds
        )
        if incidents is not None:
            self.incidents = incidents
        elif session_factory is not None:
            self.incidents = IncidentManager(session_factory, event_store, self.settings)
        else:
            self.incidents = None  # type: ignore[assignment]

    # ------------------------------------------------------------------ #
    def ingest(self, records: Sequence[RawLogRecord]) -> PipelineResult:
        """Normalize a batch of raw records and run it through the chain."""
        started = time.perf_counter()
        events, failures = registry.normalize_many(records)
        result = self.process_events(events)
        result.dlq.extend(failures)
        result.duration_ms = (time.perf_counter() - started) * 1000
        return result

    def process_events(self, events: Sequence[OcsfEvent]) -> PipelineResult:
        started = time.perf_counter()
        result = PipelineResult(events=list(events))

        if events:
            result.index_result = self.event_store.index(events)

        for event in events:
            if self.enrich_events and self.intel is not None:
                self.intel.enrich_event(event)
            for alert in self.engine.process(event):
                self._handle_alert(alert, result)

        result.duration_ms = (time.perf_counter() - started) * 1000
        return result

    # ------------------------------------------------------------------ #
    def _handle_alert(self, alert: Alert, result: PipelineResult) -> None:
        intel_hit = False
        if self.intel is not None:
            for enrichment in self.intel.enrich_alert(alert):
                if str(enrichment.value) in {"malicious", "suspicious"}:
                    intel_hit = True
        result.alerts.append(alert)

        if self.incidents is not None:
            alert, _ = self.incidents.record_alert(alert)

        hits = self.correlator.process(alert)
        result.hits.extend(hits)

        if self.incidents is None:
            return

        if hits:
            for hit in hits:
                # A correlation hit knows only the alerts in its window; pull the
                # persisted versions so the incident links stored alert rows.
                incident = self.incidents.open_from_hit(hit, intel_hit=intel_hit)
                result.incidents.append(incident)
            return

        opened = self.incidents.open_from_alert(alert)
        if opened is not None:
            result.incidents.append(opened)

    # ------------------------------------------------------------------ #
    def sweep(self) -> Dict[str, int]:
        """Expire window state.  Call periodically from a worker loop."""
        return {
            "detection_windows_dropped": self.engine.sweep(),
            "correlation_windows_dropped": self.correlator.sweep(),
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "detection": self.engine.stats.to_dict(),
            "correlation": self.correlator.stats.to_dict(),
            "intel_cache": self.intel.cache_stats if self.intel else {},
            "rules": len(self.ruleset.rules),
            "correlations": len(self.ruleset.correlations),
        }

    def reset(self) -> None:
        self.engine.reset()
        self.correlator.reset()
