"""Process-wide application state.

Built once at startup and shared by every request: the loaded rule set, the
event store, the detection pipeline and the service objects.  Keeping it in one
place makes the API a thin layer over the same engine the workers run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from signalforge.auth import AuthService
from signalforge.config import Settings, get_settings
from signalforge.correlate import CorrelationEngine
from signalforge.detect import DetectionEngine
from signalforge.enrich import ThreatIntelService
from signalforge.incidents import IncidentManager
from signalforge.pipeline import Pipeline
from signalforge.response import LabAdapter, ResponseService
from signalforge.sbom import SbomService
from signalforge.sigma import LintReport, RuleSet, lint_rules, load_ruleset
from signalforge.storage import db as dbm
from signalforge.storage.bus import EventBus, get_bus
from signalforge.storage.events import EventStore, get_event_store

log = logging.getLogger("signalforge.api")


@dataclass
class AppState:
    settings: Settings
    ruleset: RuleSet
    event_store: EventStore
    bus: EventBus
    pipeline: Pipeline
    auth: AuthService
    incidents: IncidentManager
    responses: ResponseService
    sbom: SbomService
    intel: ThreatIntelService
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    lint_report: Optional[LintReport] = None

    def reload_rules(self) -> Dict[str, Any]:
        """Re-read the detection directory without restarting the process."""
        ruleset = load_ruleset(self.settings.detections_path)
        self.ruleset = ruleset
        self.pipeline.ruleset = ruleset
        self.pipeline.engine = DetectionEngine(
            ruleset,
            settings=self.settings,
            intel_lookup=self.intel.verdict,
        )
        self.pipeline.correlator = CorrelationEngine(
            ruleset, suppression_seconds=self.settings.correlation_window_seconds
        )
        self.lint_report = lint_rules(self.settings.detections_path, require_tests=False)
        log.info(
            "rules reloaded",
            extra={"rules": len(ruleset.rules), "correlations": len(ruleset.correlations)},
        )
        return {
            "rules": len(ruleset.rules),
            "correlations": len(ruleset.correlations),
            "errors": [{"path": path, "error": error} for path, error in ruleset.errors],
        }

    def sync_detection_registry(self) -> int:
        """Mirror the loaded rules into the database, versioning any changes."""
        import hashlib
        import json

        synced = 0
        factory = dbm.get_session_factory(self.settings)
        with factory() as session:
            from sqlalchemy import select

            for kind, rules in (
                ("detection", self.ruleset.rules),
                ("correlation", self.ruleset.correlations),
            ):
                for rule in rules.values():
                    document = rule.raw or {}
                    content_hash = hashlib.sha256(
                        json.dumps(document, sort_keys=True, default=str).encode("utf-8")
                    ).hexdigest()
                    row = session.scalars(
                        select(dbm.Detection).where(dbm.Detection.rule_id == rule.id)
                    ).first()
                    if row is None:
                        row = dbm.Detection(
                            rule_id=rule.id,
                            name=rule.name,
                            title=rule.title,
                            level=rule.level,
                            status=rule.status,
                            kind=kind,
                            source_path=rule.source_path,
                            content_hash=content_hash,
                            revision=1,
                            tactics=rule.tactics,
                            techniques=rule.techniques,
                            metadata_json={"description": rule.description, "author": rule.author},
                        )
                        session.add(row)
                        session.flush()
                        session.add(
                            dbm.DetectionVersion(
                                detection_id=row.id,
                                revision=1,
                                content_hash=content_hash,
                                document=document,
                                author=rule.author,
                            )
                        )
                        synced += 1
                    elif row.content_hash != content_hash:
                        row.revision += 1
                        row.content_hash = content_hash
                        row.title = rule.title
                        row.level = rule.level
                        row.status = rule.status
                        row.tactics = rule.tactics
                        row.techniques = rule.techniques
                        session.add(
                            dbm.DetectionVersion(
                                detection_id=row.id,
                                revision=row.revision,
                                content_hash=content_hash,
                                document=document,
                                author=rule.author,
                            )
                        )
                        synced += 1
            session.commit()
        return synced


def build_state(settings: Optional[Settings] = None) -> AppState:
    settings = settings or get_settings()

    dbm.init_db(settings)
    session_factory = dbm.get_session_factory(settings)

    ruleset = load_ruleset(settings.detections_path)
    if ruleset.errors:
        for path, error in ruleset.errors:
            log.error("rule not loaded", extra={"path": path, "error": error})

    event_store = get_event_store(settings, refresh=True)
    bus = get_bus(settings, refresh=True)
    intel = ThreatIntelService(settings)
    incidents = IncidentManager(session_factory, event_store, settings)
    pipeline = Pipeline(
        ruleset,
        event_store,
        settings=settings,
        intel=intel,
        incidents=incidents,
        enrich_events=True,
    )
    auth = AuthService(session_factory, settings)
    responses = ResponseService(
        session_factory,
        settings=settings,
        incidents=incidents,
        adapter=LabAdapter(settings),
    )
    sbom = SbomService(session_factory)

    state = AppState(
        settings=settings,
        ruleset=ruleset,
        event_store=event_store,
        bus=bus,
        pipeline=pipeline,
        auth=auth,
        incidents=incidents,
        responses=responses,
        sbom=sbom,
        intel=intel,
        lint_report=lint_rules(settings.detections_path, require_tests=False),
    )

    auth.bootstrap()
    state.sync_detection_registry()
    log.info(
        "api state ready",
        extra={
            "rules": len(ruleset.rules),
            "correlations": len(ruleset.correlations),
            "event_store": settings.event_store_backend,
            "bus": settings.bus_backend,
        },
    )
    return state
