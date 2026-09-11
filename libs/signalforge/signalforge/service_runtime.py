"""Shared runtime for the streaming services.

Each service is a loop: poll a batch from the bus, process it, commit the
offsets.  Offsets are committed *after* processing, so a crash replays the batch
rather than losing it - which is safe because normalization is deterministic and
both the event store and the detection engine deduplicate on the event content
hash.

Also provides graceful shutdown (SIGINT/SIGTERM), a periodic maintenance hook
and a metrics HTTP endpoint per service.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .config import Settings, get_settings
from .logging_setup import configure_logging
from .storage.bus import Consumer, EventBus, Record, get_bus
from .telemetry import CONSUMER_LAG, setup_tracing

log = logging.getLogger("signalforge.service")


@dataclass
class ServiceStats:
    batches: int = 0
    records: int = 0
    errors: int = 0
    dlq: int = 0
    last_batch_at: Optional[float] = None
    processing_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.__dict__,
            "mean_batch_seconds": (self.processing_seconds / self.batches if self.batches else 0.0),
        }


class ConsumerService:
    """Base class for a bus consumer.

    Subclasses implement :meth:`handle_batch`.  Raising from ``handle_batch``
    means the batch is *not* committed and will be redelivered; return normally
    to commit.
    """

    #: Service name, used for logging, metrics and the consumer group suffix.
    name = "service"
    #: Topics to subscribe to.
    topics: Sequence[str] = ()
    #: Records per poll.
    batch_size = 200
    #: Poll timeout in seconds.
    poll_timeout = 0.5
    #: How often to run :meth:`maintenance`, in seconds.
    maintenance_interval = 30.0
    #: Retries before a batch is sent to the dead-letter topic.
    max_batch_attempts = 3

    def __init__(self, settings: Optional[Settings] = None, bus: Optional[EventBus] = None) -> None:
        self.settings = settings or get_settings()
        self.bus = bus or get_bus(self.settings)
        self.stats = ServiceStats()
        self._stop = asyncio.Event()
        self._consumer: Optional[Consumer] = None
        self._attempts = 0

    # -- lifecycle ---------------------------------------------------------
    @property
    def group(self) -> str:
        return "%s.%s" % (self.settings.consumer_group, self.name)

    async def setup(self) -> None:
        return None

    async def teardown(self) -> None:
        return None

    async def handle_batch(self, records: List[Record]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    async def maintenance(self) -> None:
        return None

    def request_stop(self) -> None:
        self._stop.set()

    # -- main loop ---------------------------------------------------------
    async def run(self) -> ServiceStats:
        configure_logging(self.settings.log_level, service=self.name)
        setup_tracing("signalforge-%s" % self.name, self.settings)
        await self.bus.start()
        await self.setup()
        self._consumer = self.bus.consumer(list(self.topics), self.group)
        self._install_signal_handlers()

        log.info(
            "service started",
            extra={"service": self.name, "topics": list(self.topics), "group": self.group},
        )
        last_maintenance = time.monotonic()
        try:
            while not self._stop.is_set():
                records = await self._consumer.poll(self.batch_size, self.poll_timeout)
                if records:
                    await self._process(records)
                if time.monotonic() - last_maintenance >= self.maintenance_interval:
                    await self._run_maintenance()
                    last_maintenance = time.monotonic()
        finally:
            await self._run_maintenance()
            if self._consumer is not None:
                await self._consumer.close()
            await self.teardown()
            log.info("service stopped", extra={"service": self.name, "stats": self.stats.to_dict()})
        return self.stats

    async def _process(self, records: List[Record]) -> None:
        started = time.perf_counter()
        try:
            await self.handle_batch(records)
        except Exception as exc:
            self.stats.errors += 1
            self._attempts += 1
            log.exception(
                "batch failed",
                extra={
                    "service": self.name,
                    "records": len(records),
                    "attempt": self._attempts,
                    "error": str(exc),
                },
            )
            if self._attempts >= self.max_batch_attempts:
                await self._dead_letter(records, str(exc))
                await self._consumer.commit()  # type: ignore[union-attr]
                self._attempts = 0
            else:
                # Do not commit: the batch is redelivered on the next poll.
                await asyncio.sleep(min(2**self._attempts * 0.1, 5.0))
            return

        self._attempts = 0
        await self._consumer.commit()  # type: ignore[union-attr]
        self.stats.batches += 1
        self.stats.records += len(records)
        self.stats.last_batch_at = time.time()
        self.stats.processing_seconds += time.perf_counter() - started
        for topic in self.topics:
            CONSUMER_LAG.labels(group=self.group, topic=topic).set(
                self._consumer.lag if self._consumer else 0
            )

    async def _dead_letter(self, records: List[Record], reason: str) -> None:
        for record in records:
            await self.bus.publish(
                self.settings.topic_dlq,
                {
                    "service": self.name,
                    "topic": record.topic,
                    "offset": record.offset,
                    "reason": reason,
                    "value": record.value,
                },
            )
        self.stats.dlq += len(records)
        log.error(
            "batch dead-lettered",
            extra={"service": self.name, "records": len(records), "reason": reason},
        )

    async def _run_maintenance(self) -> None:
        try:
            await self.maintenance()
        except Exception as exc:  # maintenance must never kill the loop
            log.warning("maintenance failed", extra={"service": self.name, "error": str(exc)})

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            # Windows has no signal handlers on the event loop.
            with contextlib.suppress(NotImplementedError):  # pragma: no cover
                loop.add_signal_handler(sig, self.request_stop)


def run_service(service: ConsumerService) -> ServiceStats:
    """Entry point used by every ``services/*/main.py``."""
    return asyncio.run(service.run())


def start_metrics_server(port: int) -> bool:
    """Expose ``/metrics`` for a worker process."""
    try:
        from prometheus_client import start_http_server

        from .telemetry import REGISTRY

        start_http_server(port, registry=REGISTRY)
        log.info("metrics server listening", extra={"port": port})
        return True
    except Exception as exc:  # pragma: no cover - optional dependency/port clash
        log.warning("metrics server not started", extra={"error": str(exc)})
        return False
