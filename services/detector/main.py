"""Detector service: OCSF events -> alerts.

Consumes ``sf.events.normalized``, evaluates the Sigma rule set (including
stateful aggregation rules over sliding windows), persists each alert and
publishes it to ``sf.alerts`` for the correlator and enricher.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from signalforge.config import Settings, get_settings
from signalforge.detect import DetectionEngine
from signalforge.enrich import ThreatIntelService
from signalforge.incidents import IncidentManager
from signalforge.models.ocsf import OcsfEvent
from signalforge.service_runtime import ConsumerService, run_service, start_metrics_server
from signalforge.sigma import load_ruleset
from signalforge.storage import db as dbm
from signalforge.storage.bus import Record
from signalforge.storage.events import get_event_store
from signalforge.telemetry import (
    ALERTS_SUPPRESSED,
    DETECTION_LATENCY,
    RULES_LOADED,
    WINDOWS_OPEN,
    observe,
    record_alert_metrics,
)

log = logging.getLogger("signalforge.detector")


class DetectorService(ConsumerService):
    name = "detector"

    def __init__(self, settings: Optional[Settings] = None, **kwargs: object) -> None:
        settings = settings or get_settings()
        super().__init__(settings, **kwargs)  # type: ignore[arg-type]
        self.topics = [settings.topic_normalized]
        self.batch_size = settings.max_poll_records

        self.ruleset = load_ruleset(settings.detections_path)
        for path, error in self.ruleset.errors:
            log.error("rule not loaded", extra={"path": path, "error": error})
        RULES_LOADED.labels(kind="detection").set(len(self.ruleset.rules))
        RULES_LOADED.labels(kind="correlation").set(len(self.ruleset.correlations))

        self.intel = ThreatIntelService(settings)
        self.engine = DetectionEngine(
            self.ruleset, settings=settings, intel_lookup=self.intel.verdict
        )
        dbm.init_db(settings)
        self.incidents = IncidentManager(
            dbm.get_session_factory(settings), get_event_store(settings), settings
        )

    async def handle_batch(self, records: List[Record]) -> None:
        for record in records:
            try:
                event = OcsfEvent.model_validate(record.value)
            except Exception as exc:
                log.warning("undecodable event", extra={"error": str(exc), "offset": record.offset})
                continue

            with observe(DETECTION_LATENCY):
                alerts = self.engine.process(event)

            for alert in alerts:
                self.intel.enrich_alert(alert)
                stored, created = self.incidents.record_alert(alert)
                record_alert_metrics(stored)
                await self.bus.publish(
                    self.settings.topic_alerts,
                    stored.model_dump(mode="json"),
                    key=stored.tenant,
                )
                log.info(
                    "alert published",
                    extra={
                        "rule_id": stored.rule_id,
                        "risk": stored.risk_score,
                        "new": created,
                        "principal": stored.principal,
                    },
                )

    async def maintenance(self) -> None:
        dropped = self.engine.sweep()
        stats = self.engine.stats
        WINDOWS_OPEN.labels(engine="detection").set(stats.windows_open)
        ALERTS_SUPPRESSED.labels(rule_id="*", reason="context").inc(0)
        if dropped:
            log.debug("expired detection windows", extra={"dropped": dropped})


def main() -> None:
    settings = get_settings()
    start_metrics_server(settings.metrics_port + 1)
    run_service(DetectorService(settings))


if __name__ == "__main__":
    main()
