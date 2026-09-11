"""Enricher service: attach threat intelligence to alerts.

Runs as a separate consumer group on ``sf.alerts`` so a slow or unavailable
intel provider never delays detection or correlation.  Results are cached, so
the same indicator across a thousand alerts is one lookup.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from signalforge.config import Settings, get_settings
from signalforge.enrich import ThreatIntelService
from signalforge.models.alert import Alert
from signalforge.service_runtime import ConsumerService, run_service, start_metrics_server
from signalforge.storage import db as dbm
from signalforge.storage.bus import Record
from signalforge.telemetry import INTEL_LOOKUPS
from sqlalchemy import select

log = logging.getLogger("signalforge.enricher")


class EnricherService(ConsumerService):
    name = "enricher"

    def __init__(self, settings: Optional[Settings] = None, **kwargs: object) -> None:
        settings = settings or get_settings()
        super().__init__(settings, **kwargs)  # type: ignore[arg-type]
        self.topics = [settings.topic_alerts]
        self.batch_size = 100
        self.intel = ThreatIntelService(settings)
        dbm.init_db(settings)
        self.session_factory = dbm.get_session_factory(settings)

    async def handle_batch(self, records: List[Record]) -> None:
        for record in records:
            try:
                alert = Alert.model_validate(record.value)
            except Exception as exc:
                log.warning("undecodable alert", extra={"error": str(exc)})
                continue

            enrichments = self.intel.enrich_alert(alert)
            if not enrichments:
                continue
            for enrichment in enrichments:
                INTEL_LOOKUPS.labels(provider=enrichment.provider, cache="mixed").inc()

            self._persist(alert)
            log.info(
                "alert enriched",
                extra={
                    "alert_id": alert.alert_id,
                    "indicators": len(enrichments),
                    "verdicts": [e.value for e in enrichments],
                },
            )

    def _persist(self, alert: Alert) -> None:
        """Merge enrichment back onto the stored alert without racing the detector."""
        with self.session_factory() as session:
            row = session.scalars(
                select(dbm.Alert).where(
                    dbm.Alert.tenant == alert.tenant,
                    dbm.Alert.dedup_key == alert.dedup_key,
                )
            ).first()
            if row is None:
                return
            payload = dict(row.payload or {})
            payload["enrichments"] = [
                enrichment.model_dump(mode="json") for enrichment in alert.enrichments
            ]
            payload["risk_factors"] = alert.risk_factors
            row.payload = payload
            dbm.record_audit(
                session,
                tenant=alert.tenant,
                actor="enricher",
                action="alert.enriched",
                entity_type="alert",
                entity_id=row.id,
                indicators=len(alert.enrichments),
            )
            session.commit()

    async def maintenance(self) -> None:
        stats = self.intel.cache_stats
        if stats:
            log.debug("intel cache", extra=stats)


def main() -> None:
    settings = get_settings()
    start_metrics_server(settings.metrics_port + 3)
    run_service(EnricherService(settings))


if __name__ == "__main__":
    main()
