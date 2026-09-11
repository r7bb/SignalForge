#!/usr/bin/env python3
"""Walk one attack-shaped sequence through the whole pipeline, printing each hop.

    python scripts/demo.py
    python scripts/demo.py --scenario account_compromise
    python scripts/demo.py --list

Nothing here touches a network: telemetry is generated in-process, stored in the
in-memory event store and SQLite, and evaluated by the real engine.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "libs" / "signalforge"))

os.environ.setdefault("SIGNALFORGE_BUS_BACKEND", "memory")
os.environ.setdefault("SIGNALFORGE_EVENT_STORE_BACKEND", "memory")
os.environ.setdefault(
    "SIGNALFORGE_DATABASE_URL",
    "sqlite+pysqlite:///%s" % Path(tempfile.gettempdir(), "signalforge-demo.db"),
)

from signalforge.attack import kill_chain  # noqa: E402
from signalforge.config import get_settings  # noqa: E402
from signalforge.correlate.risk import risk_level  # noqa: E402
from signalforge.enrich import ThreatIntelService  # noqa: E402
from signalforge.incidents import IncidentManager  # noqa: E402
from signalforge.lab import SCENARIOS, TelemetryGenerator  # noqa: E402
from signalforge.pipeline import Pipeline  # noqa: E402
from signalforge.sigma import load_ruleset  # noqa: E402
from signalforge.storage import db as dbm  # noqa: E402
from signalforge.storage.events import InMemoryEventStore  # noqa: E402

RULE = "─" * 78


def heading(text: str) -> None:
    print("\n%s\n%s\n%s" % (RULE, text, RULE))


def main() -> int:
    parser = argparse.ArgumentParser(description="SignalForge end-to-end demo")
    parser.add_argument(
        "--scenario",
        default="account_compromise",
        help="scenario name (default: account_compromise)",
    )
    parser.add_argument("--list", action="store_true", help="list the scenarios and exit")
    parser.add_argument(
        "--noise", type=int, default=0, help="baseline events to mix in (default: 0)"
    )
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    if args.list:
        for scenario in SCENARIOS.values():
            print("%-22s %s" % (scenario.name, scenario.description.strip().splitlines()[0]))
        return 0

    if args.scenario not in SCENARIOS:
        print("unknown scenario %r; try --list" % args.scenario, file=sys.stderr)
        return 2

    settings = get_settings()
    dbm.init_db(settings, drop=True)
    ruleset = load_ruleset(settings.detections_path)
    if ruleset.errors:
        for path, error in ruleset.errors:
            print("rule not loaded: %s (%s)" % (path, error), file=sys.stderr)

    event_store = InMemoryEventStore()
    incidents = IncidentManager(dbm.get_session_factory(settings), event_store, settings)
    intel = ThreatIntelService(settings)
    pipeline = Pipeline(
        ruleset,
        event_store,
        settings=settings,
        intel=intel,
        incidents=incidents,
        enrich_events=True,
    )

    heading("SignalForge - %s" % SCENARIOS[args.scenario].title)
    print(
        "rules loaded          : %d detections, %d correlations"
        % (len(ruleset.rules), len(ruleset.correlations))
    )
    print("expected detections   : %s" % ", ".join(SCENARIOS[args.scenario].expected_detections))

    generator = TelemetryGenerator(tenant=settings.bootstrap_tenant, seed=args.seed)
    start = datetime.now(tz=timezone.utc) - timedelta(minutes=20)
    records = []
    if args.noise:
        records.extend(generator.normal_activity(args.noise, start, spread_seconds=1200))
    records.extend(generator.scenario(args.scenario, start))
    records.sort(key=lambda record: record.received_at)

    heading("1. Ingestion and OCSF normalization")
    result = pipeline.ingest(records)
    for event in result.events[-12:]:
        print(
            "%s  %-14s %-34s %-8s %-22s %s"
            % (
                event.time.strftime("%H:%M:%S"),
                event.sf_source or "-",
                (event.type_name or event.class_name or "")[:34],
                event.status or "-",
                event.principal or "-",
                event.source_ip or "-",
            )
        )
    print(
        "\n%d records -> %d events (%d duplicates, %d dead-lettered)"
        % (
            len(records),
            result.counts["events"],
            result.counts["duplicates"],
            result.counts["dlq"],
        )
    )

    heading("2. Sigma detections")
    if not result.alerts:
        print("no alerts (try --noise 200, or a different scenario)")
    for alert in result.alerts:
        print(
            "ALERT  %-14s %-42s risk %3d (%s)"
            % (
                alert.rule_id,
                alert.rule_title[:42],
                alert.risk_score,
                alert.risk_level,
            )
        )
        print("       %s" % "; ".join(alert.risk_factors[:4]))
        if alert.detection.event_count > 1:
            print(
                "       %d events inside %ss"
                % (alert.detection.event_count, alert.detection.timeframe_seconds)
            )

    heading("3. Correlation")
    if not result.hits:
        print("no correlation fired")
    for hit in result.hits:
        print(
            "CORR   %-14s %-42s %d stages"
            % (
                hit.correlation.id,
                hit.correlation.title[:42],
                len(hit.alerts),
            )
        )
        print("       sequence: %s" % " -> ".join(hit.sequence))
        print("       grouped by: %s" % ", ".join(hit.group_key))

    heading("4. Incidents")
    for incident in incidents.list(settings.bootstrap_tenant, limit=10):
        print(
            "%-9s %-40s risk %3d/100  %-8s %s"
            % (
                incident.key,
                incident.title[:40],
                incident.risk_score,
                risk_level(incident.risk_score),
                incident.status.value,
            )
        )
        if incident.close_reason:
            # A completed chain absorbs the stage incidents opened before it.
            print("          %s" % incident.close_reason)
        print("          %s" % " -> ".join(step["name"] for step in kill_chain(incident.tactics)))
        print(
            "          %d alerts, %d events, principal %s"
            % (
                len(incident.alert_ids),
                incident.evidence_count,
                incident.principal or "-",
            )
        )
        for factor in incident.risk_factors:
            print("          · %s" % factor)

    incidents_list = incidents.list(settings.bootstrap_tenant, limit=1)
    if incidents_list:
        heading("5. Investigation timeline for %s" % incidents_list[0].key)
        for entry in incidents.build_timeline(
            settings.bootstrap_tenant, incidents_list[0].key, size=25
        ):
            print(
                "%s  %-9s %-40s %s"
                % (
                    entry.time.strftime("%H:%M:%S"),
                    entry.kind,
                    entry.title[:40],
                    entry.detail or entry.actor or "",
                )
            )

    heading("Pipeline stats")
    stats = pipeline.stats
    print("events processed      : %d" % stats["detection"]["events_processed"])
    print("duplicates skipped    : %d" % stats["detection"]["events_deduped"])
    print("rules evaluated       : %d" % stats["detection"]["rules_evaluated"])
    print("alerts emitted        : %d" % stats["detection"]["alerts_emitted"])
    print("alerts suppressed     : %d" % stats["detection"]["alerts_suppressed"])
    print("mean detection latency: %.3f ms" % stats["detection"]["mean_latency_ms"])
    print("intel cache           : %s" % stats["intel_cache"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
