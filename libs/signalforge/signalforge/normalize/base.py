"""Normalizer plumbing: the mapper contract and the source registry."""

from __future__ import annotations

import logging
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ..models.ocsf import OcsfEvent, RawLogRecord

log = logging.getLogger("signalforge.normalize")


class NormalizationError(Exception):
    """Raised when a record cannot be mapped; the caller routes it to the DLQ."""

    def __init__(self, message: str, record: Optional[RawLogRecord] = None) -> None:
        super().__init__(message)
        self.record = record


class Mapper:
    """Maps one log source family into OCSF.

    ``source`` is matched against ``RawLogRecord.source`` as an exact value or
    as a dotted prefix, so a mapper registered for ``linux`` handles
    ``linux.sshd`` and ``linux.sudo``.
    """

    source: str = ""
    product_name: str = ""
    vendor_name: str = ""

    def matches(self, record: RawLogRecord) -> bool:
        src = (record.source or "").lower()
        return src == self.source or src.startswith(self.source + ".")

    def map(self, record: RawLogRecord) -> Optional[OcsfEvent]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- helpers available to subclasses ----------------------------------
    def stamp(self, event: OcsfEvent, record: RawLogRecord) -> OcsfEvent:
        event.sf_tenant = record.tenant
        event.sf_source = record.source
        event.sf_raw = record.raw
        event.metadata.product.name = event.metadata.product.name or self.product_name
        event.metadata.product.vendor_name = (
            event.metadata.product.vendor_name or self.vendor_name
        )
        event.metadata.log_provider = event.metadata.log_provider or record.collector
        event.metadata.processed_time = event.metadata.processed_time or record.received_at
        event.metadata.original_time = event.metadata.original_time or (
            str(record.payload.get("timestamp") or record.payload.get("eventTime") or "") or None
        )
        event.sf_dedup_key = event.compute_dedup_key()
        return event.derive_observables()


class MapperRegistry:
    """Ordered collection of mappers with longest-prefix-wins resolution."""

    def __init__(self) -> None:
        self._mappers: List[Mapper] = []

    def register(self, mapper: Mapper) -> Mapper:
        self._mappers.append(mapper)
        # Longest source first so "linux.sshd" beats a generic "linux" mapper.
        self._mappers.sort(key=lambda m: len(m.source), reverse=True)
        return mapper

    def resolve(self, record: RawLogRecord) -> Optional[Mapper]:
        for mapper in self._mappers:
            if mapper.matches(record):
                return mapper
        return None

    @property
    def sources(self) -> List[str]:
        return [mapper.source for mapper in self._mappers]

    def normalize(self, record: RawLogRecord) -> OcsfEvent:
        mapper = self.resolve(record)
        if mapper is None:
            raise NormalizationError("no mapper for source %r" % record.source, record)
        try:
            event = mapper.map(record)
        except NormalizationError:
            raise
        except Exception as exc:  # defensive: a bad log line must not kill the worker
            raise NormalizationError(
                "mapper %s failed: %s" % (type(mapper).__name__, exc), record
            ) from exc
        if event is None:
            raise NormalizationError(
                "mapper %s could not classify record" % type(mapper).__name__, record
            )
        return mapper.stamp(event, record)

    def normalize_many(
        self, records: Iterable[RawLogRecord]
    ) -> Tuple[List[OcsfEvent], List[Tuple[RawLogRecord, str]]]:
        """Normalize a batch, returning ``(events, failures)``."""
        events: List[OcsfEvent] = []
        failures: List[Tuple[RawLogRecord, str]] = []
        for record in records:
            try:
                events.append(self.normalize(record))
            except NormalizationError as exc:
                log.warning("normalization failed", extra={"source": record.source, "error": str(exc)})
                failures.append((record, str(exc)))
        return events, failures


registry = MapperRegistry()


def register(mapper_cls: Callable[[], Mapper]) -> Callable[[], Mapper]:
    """Class decorator that instantiates and registers a mapper."""
    registry.register(mapper_cls())
    return mapper_cls
