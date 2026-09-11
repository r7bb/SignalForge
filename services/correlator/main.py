"""Correlator service: alerts -> incidents.

Consumes ``sf.alerts``, feeds each alert into the Sigma correlation rules and
turns a satisfied correlation into an incident (or extends the existing one).
Alerts that are severe enough on their own also open an incident, so nothing
above the single-alert threshold sits unowned in the queue.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from signalforge.config import Settings, get_settings
from signalforge.correlate import CorrelationEngine
from signalforge.incidents import IncidentManager
from signalforge.models.alert import Alert
from signalforge.service_runtime import ConsumerService, run_service, start_metrics_server
from signalforge.sigma import load_ruleset
from signalforge.storage import db as dbm
from signalforge.storage.bus import Record
from signalforge.storage.events import get_event_store
from signalforge.telemetry import CORRELATIONS, INCIDENTS, WINDOWS_OPEN

log = logging.getLogger("signalforge.correlator")


class CorrelatorService(ConsumerService):
    name = "correlator"

    def __init__(self, settings: Optional[Settings] = None, **kwargs: object) -> None:
        settings = settings or get_settings()
        super().__init__(settings, **kwargs)  # type: ignore[arg-type]
        self.topics = [settings.topic_alerts]
        self.batch_size = 100

        self.ruleset = load_ruleset(settings.detections_path)
        self.correlator = CorrelationEngine(
            self.ruleset, suppression_seconds=settings.correlation_window_seconds
        )
        dbm.init_db(settings)
        self.incidents = IncidentManager(
            dbm.get_session_factory(settings), get_event_store(settings), settings
        )

    async def handle_batch(self, records: List[Record]) -> None:
        for record in records:
            try:
                alert = Alert.model_validate(record.value)
            except Exception as exc:
                log.warning("undecodable alert", extra={"error": str(exc), "offset": record.offset})
                continue

            intel_hit = any(
                str(enrichment.value) in {"malicious", "suspicious"}
                for enrichment in alert.enrichments
            )
            hits = self.correlator.process(alert)

            if not hits:
                incident = self.incidents.open_from_alert(alert)
                if incident is not None:
                    INCIDENTS.labels(action="opened_single", severity=incident.severity.value).inc()
                    log.info(
                        "incident from single alert",
                        extra={"key": incident.key, "risk": incident.risk_score},
                    )
                continue

            for hit in hits:
                CORRELATIONS.labels(correlation_id=hit.correlation.id, scenario=hit.scenario).inc()
                incident = self.incidents.open_from_hit(hit, intel_hit=intel_hit)
                INCIDENTS.labels(action="correlated", severity=incident.severity.value).inc()
                log.info(
                    "incident correlated",
                    extra={
                        "key": incident.key,
                        "risk": incident.risk_score,
                        "scenario": hit.scenario,
                        "stages": hit.sequence,
                    },
                )

    async def maintenance(self) -> None:
        dropped = self.correlator.sweep()
        WINDOWS_OPEN.labels(engine="correlation").set(self.correlator.stats.windows_open)
        if dropped:
            log.debug("expired correlation windows", extra={"dropped": dropped})


def main() -> None:
    settings = get_settings()
    start_metrics_server(settings.metrics_port + 2)
    run_service(CorrelatorService(settings))


if __name__ == "__main__":
    main()
