"""Collector service: get logs onto the bus.

Three modes, chosen with ``SIGNALFORGE_COLLECTOR_MODE``:

``file``   tail one or more files (the shape Vector/Fluent Bit write), with a
           persisted byte offset per file so a restart resumes where it left off;
``stdin``  read newline-delimited records from stdin (handy in a pipeline);
``lab``    generate synthetic telemetry with the bundled generator.

Every mode produces the same ``RawLogRecord`` envelope on ``sf.logs.raw``.  In
production the recommended path is Vector -> Kafka directly (see
``infrastructure/vector/vector.yaml``); this service exists so the platform is
self-contained without it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence

from signalforge.config import Settings, get_settings
from signalforge.lab import SCENARIOS, TelemetryGenerator
from signalforge.logging_setup import configure_logging
from signalforge.models.ocsf import RawLogRecord
from signalforge.service_runtime import start_metrics_server
from signalforge.storage.bus import EventBus, get_bus
from signalforge.telemetry import EVENTS_INGESTED

log = logging.getLogger("signalforge.collector")


@dataclass
class FileSource:
    """One tailed file and the source key its lines map to."""

    path: Path
    source: str
    tenant: str = "acme"


def parse_file_sources(spec: str, tenant: str) -> List[FileSource]:
    """``/var/log/auth.log:linux.sshd,/var/log/app.json:app.audit``."""
    sources: List[FileSource] = []
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        path, _, source = entry.partition(":")
        sources.append(FileSource(Path(path), source or "linux.sshd", tenant))
    return sources


class OffsetStore:
    """Byte offsets per file, so a restart does not re-send the whole log."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._offsets: Dict[str, int] = {}
        if path.exists():
            try:
                self._offsets = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                log.warning("could not read offsets; starting from the top")

    def get(self, key: str) -> int:
        return int(self._offsets.get(key, 0))

    def set(self, key: str, value: int) -> None:
        self._offsets[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._offsets), encoding="utf-8")


class Collector:
    def __init__(self, settings: Optional[Settings] = None, bus: Optional[EventBus] = None) -> None:
        self.settings = settings or get_settings()
        self.bus = bus or get_bus(self.settings)
        self.tenant = os.environ.get("SIGNALFORGE_COLLECTOR_TENANT", self.settings.bootstrap_tenant)
        self.mode = os.environ.get("SIGNALFORGE_COLLECTOR_MODE", "lab").lower()
        self.offsets = OffsetStore(
            Path(os.environ.get("SIGNALFORGE_COLLECTOR_OFFSETS", "var/collector-offsets.json"))
        )
        self.batch_size = int(os.environ.get("SIGNALFORGE_COLLECTOR_BATCH", "200"))
        self.interval = float(os.environ.get("SIGNALFORGE_COLLECTOR_INTERVAL", "2.0"))
        self._stop = False

    # ------------------------------------------------------------------ #
    async def publish(self, records: Sequence[RawLogRecord]) -> int:
        for record in records:
            EVENTS_INGESTED.labels(source=record.source, tenant=record.tenant).inc()
            await self.bus.publish(
                self.settings.topic_raw, record.model_dump(mode="json"), key=record.tenant
            )
        return len(records)

    # ------------------------------------------------------------------ #
    async def run(self) -> int:
        configure_logging(self.settings.log_level, service="collector")
        await self.bus.start()
        log.info("collector starting", extra={"mode": self.mode, "tenant": self.tenant})
        try:
            if self.mode == "file":
                return await self.run_files()
            if self.mode == "stdin":
                return await self.run_stdin()
            return await self.run_lab()
        finally:
            await self.bus.stop()

    async def run_files(self) -> int:
        spec = os.environ.get("SIGNALFORGE_COLLECTOR_FILES", "")
        sources = parse_file_sources(spec, self.tenant)
        if not sources:
            log.error("file mode needs SIGNALFORGE_COLLECTOR_FILES")
            return 0
        total = 0
        while not self._stop:
            for source in sources:
                total += await self.publish(list(self._read_new_lines(source)))
            await asyncio.sleep(self.interval)
        return total

    def _read_new_lines(self, source: FileSource) -> Iterator[RawLogRecord]:
        if not source.path.exists():
            return
        key = str(source.path)
        offset = self.offsets.get(key)
        size = source.path.stat().st_size
        if size < offset:
            # The file was rotated or truncated: start again from the top.
            log.info("file rotated, restarting from offset 0", extra={"path": key})
            offset = 0
        with source.path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            count = 0
            for line in handle:
                line = line.rstrip("\n")
                if not line:
                    continue
                yield self._to_record(line, source)
                count += 1
                if count >= self.batch_size:
                    break
            self.offsets.set(key, handle.tell())

    @staticmethod
    def _to_record(line: str, source: FileSource) -> RawLogRecord:
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                payload = json.loads(stripped)
                # Vector-style envelopes carry the original line under "message".
                return RawLogRecord(
                    source=str(payload.get("sf_source") or source.source),
                    tenant=str(payload.get("sf_tenant") or source.tenant),
                    payload=payload,
                    raw=payload.get("message") if isinstance(payload.get("message"), str) else None,
                    collector="collector.file",
                )
            except json.JSONDecodeError:
                pass
        return RawLogRecord(
            source=source.source, tenant=source.tenant, raw=line, collector="collector.file"
        )

    async def run_stdin(self) -> int:
        total = 0
        default_source = os.environ.get("SIGNALFORGE_COLLECTOR_SOURCE", "linux.sshd")
        source = FileSource(Path("-"), default_source, self.tenant)
        batch: List[RawLogRecord] = []
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            batch.append(self._to_record(line, source))
            if len(batch) >= self.batch_size:
                total += await self.publish(batch)
                batch = []
        if batch:
            total += await self.publish(batch)
        log.info("stdin drained", extra={"records": total})
        return total

    async def run_lab(self) -> int:
        """Continuously emit lab telemetry, with a scenario every few cycles."""
        generator = TelemetryGenerator(tenant=self.tenant)
        rate = int(os.environ.get("SIGNALFORGE_COLLECTOR_RATE", "20"))
        scenario_every = int(os.environ.get("SIGNALFORGE_COLLECTOR_SCENARIO_EVERY", "10"))
        scenarios = sorted(SCENARIOS)
        total = 0
        cycle = 0
        while not self._stop:
            cycle += 1
            total += await self.publish(generator.normal_activity(rate, spread_seconds=1))
            if scenario_every and cycle % scenario_every == 0:
                name = scenarios[(cycle // scenario_every - 1) % len(scenarios)]
                log.info("emitting scenario", extra={"scenario": name})
                total += await self.publish(generator.scenario(name))
            await asyncio.sleep(1.0)
        return total

    def stop(self) -> None:
        self._stop = True


def main() -> None:
    settings = get_settings()
    start_metrics_server(settings.metrics_port + 4)
    asyncio.run(Collector(settings).run())


if __name__ == "__main__":
    main()
