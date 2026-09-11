"""Normalizer service: raw log records -> OCSF events.

Consumes ``sf.logs.raw``, maps each record with the source registry, writes the
result to the security event store (idempotently, keyed by content hash) and
publishes the normalized event to ``sf.events.normalized``.  Records that no
mapper understands go to the dead-letter topic with the reason attached rather
than being dropped.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from signalforge.config import Settings, get_settings
from signalforge.models.ocsf import RawLogRecord
from signalforge.normalize import registry
from signalforge.service_runtime import ConsumerService, run_service, start_metrics_server
from signalforge.storage.bus import Record
from signalforge.storage.events import EventStore, get_event_store
from signalforge.telemetry import (
    EVENTS_NORMALIZED,
    INDEX_LATENCY,
    NORMALIZATION_FAILURES,
    SPOOLED_EVENTS,
    observe,
)

log = logging.getLogger("signalforge.normalizer")


class NormalizerService(ConsumerService):
    name = "normalizer"

    def __init__(
        self,
        settings: Optional[Settings] = None,
        event_store: Optional[EventStore] = None,
        **kwargs: object,
    ) -> None:
        settings = settings or get_settings()
        super().__init__(settings, **kwargs)  # type: ignore[arg-type]
        self.topics = [settings.topic_raw]
        self.batch_size = settings.max_poll_records
        self.event_store = event_store or get_event_store(settings)

    async def handle_batch(self, records: List[Record]) -> None:
        raw_records = []
        for record in records:
            try:
                raw_records.append(RawLogRecord.model_validate(record.value))
            except Exception as exc:
                NORMALIZATION_FAILURES.labels(source="unparseable", reason="schema").inc()
                log.warning(
                    "malformed bus record", extra={"error": str(exc), "offset": record.offset}
                )

        events, failures = registry.normalize_many(raw_records)

        for raw_record, reason in failures:
            NORMALIZATION_FAILURES.labels(
                source=raw_record.source, reason=reason.split(":")[0][:40]
            ).inc()
            await self.bus.publish(
                self.settings.topic_dlq,
                {
                    "service": self.name,
                    "reason": reason,
                    "record": raw_record.model_dump(mode="json"),
                },
            )

        if not events:
            return

        with observe(INDEX_LATENCY):
            result = self.event_store.index(events)
        if result.spooled:
            log.error("event store unavailable; events spooled", extra={"spooled": result.spooled})

        for event in events:
            EVENTS_NORMALIZED.labels(
                source=event.sf_source or "unknown",
                class_name=event.class_name or "unknown",
            ).inc()
            await self.bus.publish(
                self.settings.topic_normalized,
                event.to_document(),
                key=event.sf_tenant,
            )

    async def maintenance(self) -> None:
        """Retry anything the event store could not accept earlier."""
        result = self.event_store.flush_spool()
        if result.indexed:
            log.info("spool flushed", extra={"indexed": result.indexed})
        spooled = getattr(self.event_store, "spooled_count", 0)
        SPOOLED_EVENTS.set(spooled)


def main() -> None:
    settings = get_settings()
    start_metrics_server(settings.metrics_port)
    run_service(NormalizerService(settings))


if __name__ == "__main__":
    main()
