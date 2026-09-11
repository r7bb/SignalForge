"""Throughput and latency harness.

Skipped unless ``SIGNALFORGE_RUN_LOAD=1`` so the normal suite stays fast:

    SIGNALFORGE_RUN_LOAD=1 pytest tests/load -s

It measures the same numbers ``scripts/benchmark.py`` reports, and asserts only
on *loss* (which must be zero) rather than on absolute speed - a CI runner's
throughput is not a meaningful threshold.
"""

from __future__ import annotations

import os
import statistics
import time
from datetime import datetime, timezone
from typing import Dict, List

import pytest
from signalforge.detect import DetectionEngine
from signalforge.incidents import IncidentManager
from signalforge.lab import TelemetryGenerator
from signalforge.normalize import registry
from signalforge.pipeline import Pipeline
from signalforge.storage.events import EventQuery

pytestmark = [
    pytest.mark.load,
    pytest.mark.slow,
    pytest.mark.skipif(
        os.environ.get("SIGNALFORGE_RUN_LOAD") != "1",
        reason="set SIGNALFORGE_RUN_LOAD=1 to run the load harness",
    ),
]

BASE = datetime(2026, 9, 10, 13, 0, tzinfo=timezone.utc)
EVENT_COUNT = int(os.environ.get("SIGNALFORGE_LOAD_EVENTS", "20000"))
BATCH_SIZE = int(os.environ.get("SIGNALFORGE_LOAD_BATCH", "500"))


def report(name: str, values: Dict[str, float]) -> None:
    print("\n=== %s ===" % name)
    for key, value in values.items():
        print("%-28s %s" % (key, ("%.3f" % value) if isinstance(value, float) else value))


def test_normalization_throughput() -> None:
    generator = TelemetryGenerator(tenant="acme", seed=1)
    records = generator.normal_activity(EVENT_COUNT, BASE, spread_seconds=EVENT_COUNT // 10)

    started = time.perf_counter()
    events, failures = registry.normalize_many(records)
    elapsed = time.perf_counter() - started

    report(
        "normalization",
        {
            "records": len(records),
            "events": len(events),
            "failures": len(failures),
            "seconds": elapsed,
            "events_per_second": len(events) / elapsed,
        },
    )
    assert not failures, "the generator must only emit shapes the mappers understand"
    assert len(events) == len(records)


def test_detection_latency_distribution(ruleset) -> None:
    generator = TelemetryGenerator(tenant="acme", seed=2)
    events, _ = registry.normalize_many(
        generator.normal_activity(EVENT_COUNT, BASE, spread_seconds=EVENT_COUNT // 10)
    )
    engine = DetectionEngine(ruleset)

    latencies: List[float] = []
    started = time.perf_counter()
    for event in events:
        event_started = time.perf_counter()
        engine.process(event)
        latencies.append((time.perf_counter() - event_started) * 1000)
    elapsed = time.perf_counter() - started

    latencies.sort()
    percentile = lambda p: latencies[min(int(len(latencies) * p), len(latencies) - 1)]  # noqa: E731
    report(
        "detection",
        {
            "events": len(events),
            "seconds": elapsed,
            "events_per_second": len(events) / elapsed,
            "mean_ms": statistics.fmean(latencies),
            "p50_ms": percentile(0.50),
            "p95_ms": percentile(0.95),
            "p99_ms": percentile(0.99),
            "max_ms": latencies[-1],
            "rules_evaluated": engine.stats.rules_evaluated,
            "alerts": engine.stats.alerts_emitted,
            "windows_open": engine.stats.windows_open,
        },
    )
    assert engine.stats.events_processed == len(events)


def test_end_to_end_pipeline_loses_nothing(ruleset, event_store, session_factory, settings) -> None:
    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)

    generator = TelemetryGenerator(tenant="acme", seed=3)
    records = generator.normal_activity(EVENT_COUNT, BASE, spread_seconds=EVENT_COUNT // 10)

    accepted = 0
    started = time.perf_counter()
    for offset in range(0, len(records), BATCH_SIZE):
        result = pipeline.ingest(records[offset : offset + BATCH_SIZE])
        accepted += result.index_result.accepted if result.index_result else 0
    elapsed = time.perf_counter() - started

    stored = event_store.search(EventQuery(tenant="acme", size=0)).total
    report(
        "end to end",
        {
            "records": len(records),
            "accepted": accepted,
            "stored": stored,
            "seconds": elapsed,
            "events_per_second": len(records) / elapsed,
            "alerts": pipeline.engine.stats.alerts_emitted,
            "incidents": len(incidents.list("acme", limit=500)),
            "mean_detection_ms": pipeline.engine.stats.mean_latency_ms,
        },
    )

    # The assertion that matters: nothing is silently dropped. Some generated
    # records are genuinely identical (same principal, action and second), and
    # those collapse by content hash - so accounted-for, not stored, is the
    # invariant.
    assert accepted == len(records)
    assert stored + pipeline.engine.stats.events_deduped == len(records)


def test_sustained_rate_keeps_up_with_the_generator(
    ruleset, event_store, session_factory, settings
) -> None:
    """Feed at a target logical rate and report the achieved rate."""
    target_rate = int(os.environ.get("SIGNALFORGE_LOAD_RATE", "5000"))
    duration = int(os.environ.get("SIGNALFORGE_LOAD_DURATION", "4"))

    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)
    generator = TelemetryGenerator(tenant="acme", seed=4)

    batch: List = []
    processed = 0
    started = time.perf_counter()
    for record in generator.stream(target_rate, duration, BASE):
        batch.append(record)
        if len(batch) >= BATCH_SIZE:
            pipeline.ingest(batch)
            processed += len(batch)
            batch = []
    if batch:
        pipeline.ingest(batch)
        processed += len(batch)
    elapsed = time.perf_counter() - started

    achieved = processed / elapsed
    report(
        "sustained rate",
        {
            "target_rate": target_rate,
            "logical_events": processed,
            "seconds": elapsed,
            "achieved_events_per_second": achieved,
            "keeps_up": achieved >= target_rate,
            "spooled": getattr(event_store, "spooled_count", 0),
        },
    )
    stored = event_store.search(EventQuery(tenant="acme", size=0)).total
    assert stored + pipeline.engine.stats.events_deduped == processed
