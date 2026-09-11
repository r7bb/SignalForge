#!/usr/bin/env python3
"""Measure ingestion throughput, detection latency and event loss.

    python scripts/benchmark.py --rate 5000 --duration 30
    python scripts/benchmark.py --events 100000 --report benchmarks/run.json

Reports achieved events/sec, mean/p50/p95/p99 detection latency, alert and
incident counts, and whether anything was dropped.  Run it against the
in-process backends for a pure engine number, or point the settings at
OpenSearch/PostgreSQL to include storage.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "libs" / "signalforge"))

os.environ.setdefault("SIGNALFORGE_BUS_BACKEND", "memory")
os.environ.setdefault("SIGNALFORGE_EVENT_STORE_BACKEND", "memory")
os.environ.setdefault("SIGNALFORGE_DATABASE_URL", "sqlite+pysqlite:///./benchmark.db")

from signalforge.config import get_settings  # noqa: E402
from signalforge.incidents import IncidentManager  # noqa: E402
from signalforge.lab import TelemetryGenerator  # noqa: E402
from signalforge.normalize import registry  # noqa: E402
from signalforge.pipeline import Pipeline  # noqa: E402
from signalforge.sigma import load_ruleset  # noqa: E402
from signalforge.storage import db as dbm  # noqa: E402
from signalforge.storage.events import EventQuery, get_event_store  # noqa: E402


def percentile(sorted_values: List[float], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(int(len(sorted_values) * fraction), len(sorted_values) - 1)
    return sorted_values[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="SignalForge benchmark")
    parser.add_argument(
        "--events", type=int, default=0, help="total events to push (overrides --rate/--duration)"
    )
    parser.add_argument("--rate", type=int, default=1000, help="logical events per second")
    parser.add_argument("--duration", type=int, default=10, help="seconds of telemetry")
    parser.add_argument("--batch", type=int, default=500, help="ingest batch size")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--report", help="write the results as JSON to this path")
    parser.add_argument("--tenant", default="acme")
    args = parser.parse_args()

    total = args.events or args.rate * args.duration
    settings = get_settings()
    dbm.init_db(settings, drop=True)

    ruleset = load_ruleset(settings.detections_path)
    event_store = get_event_store(settings, refresh=True)
    incidents = IncidentManager(dbm.get_session_factory(settings), event_store, settings)
    pipeline = Pipeline(ruleset, event_store, settings=settings, incidents=incidents)

    generator = TelemetryGenerator(tenant=args.tenant, seed=args.seed)
    start = datetime.now(tz=timezone.utc) - timedelta(seconds=total // max(args.rate, 1))

    print("generating %d records..." % total)
    generate_started = time.perf_counter()
    records = generator.normal_activity(total, start, spread_seconds=max(total // 10, 1))
    generate_seconds = time.perf_counter() - generate_started

    print("normalizing...")
    normalize_started = time.perf_counter()
    events, failures = registry.normalize_many(records)
    normalize_seconds = time.perf_counter() - normalize_started

    print("running the pipeline...")
    latencies: List[float] = []
    accepted = 0
    pipeline_started = time.perf_counter()
    for offset in range(0, len(events), args.batch):
        batch = events[offset : offset + args.batch]
        batch_started = time.perf_counter()
        result = pipeline.process_events(batch)
        elapsed = (time.perf_counter() - batch_started) * 1000
        latencies.append(elapsed / max(len(batch), 1))
        accepted += result.index_result.accepted if result.index_result else 0
    pipeline_seconds = time.perf_counter() - pipeline_started

    stored = event_store.search(EventQuery(tenant=args.tenant, size=0)).total
    latencies.sort()
    engine_stats = pipeline.engine.stats

    results: Dict[str, Any] = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "cpu_count": os.cpu_count(),
            "event_store": settings.event_store_backend,
            "bus": settings.bus_backend,
            "database": settings.database_url.split("://", 1)[0],
        },
        "workload": {
            "records": len(records),
            "events": len(events),
            "normalization_failures": len(failures),
            "batch_size": args.batch,
            "requested_rate": args.rate,
        },
        "throughput": {
            "generation_events_per_second": len(records) / generate_seconds,
            "normalization_events_per_second": len(events) / normalize_seconds,
            "pipeline_events_per_second": len(events) / pipeline_seconds,
            "pipeline_seconds": pipeline_seconds,
        },
        "detection_latency_ms": {
            "mean": statistics.fmean(latencies) if latencies else 0.0,
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "max": latencies[-1] if latencies else 0.0,
            "engine_mean": engine_stats.mean_latency_ms,
        },
        "outcomes": {
            "accepted": accepted,
            "stored": stored,
            # Generated records can be genuinely identical (same principal,
            # action and second); those collapse by content hash and are not
            # losses. Anything unaccounted for after that is.
            "deduplicated": engine_stats.events_deduped,
            "lost": len(events) - stored - engine_stats.events_deduped,
            "rules_evaluated": engine_stats.rules_evaluated,
            "alerts": engine_stats.alerts_emitted,
            "alerts_deduped": engine_stats.alerts_deduped,
            "alerts_suppressed": engine_stats.alerts_suppressed,
            "incidents": len(incidents.list(args.tenant, limit=1000)),
            "windows_open": engine_stats.windows_open,
        },
    }

    print()
    print("=" * 70)
    print(
        "throughput (pipeline)   : %.0f events/sec"
        % results["throughput"]["pipeline_events_per_second"]
    )
    print(
        "throughput (normalize)  : %.0f events/sec"
        % results["throughput"]["normalization_events_per_second"]
    )
    print("detection latency p50   : %.3f ms" % results["detection_latency_ms"]["p50"])
    print("detection latency p95   : %.3f ms" % results["detection_latency_ms"]["p95"])
    print("detection latency p99   : %.3f ms" % results["detection_latency_ms"]["p99"])
    print("events stored           : %d / %d" % (stored, len(events)))
    print("deduplicated            : %d" % results["outcomes"]["deduplicated"])
    print("events lost             : %d" % results["outcomes"]["lost"])
    print(
        "alerts / incidents      : %d / %d"
        % (results["outcomes"]["alerts"], results["outcomes"]["incidents"])
    )
    print("=" * 70)

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print("report written to %s" % report_path)

    return 0 if results["outcomes"]["lost"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
