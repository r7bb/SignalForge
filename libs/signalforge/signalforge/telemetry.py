"""Platform telemetry: Prometheus metrics and optional OpenTelemetry tracing.

Both are optional at runtime.  If ``prometheus_client`` is missing the metric
objects degrade to no-ops, and tracing is only wired up when
``SIGNALFORGE_OTEL_ENABLED`` is set, so a bare ``pip install`` still runs.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from .config import Settings, get_settings

log = logging.getLogger("signalforge.telemetry")

try:  # pragma: no cover - exercised implicitly by the metrics endpoint
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    PROMETHEUS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"

    class _Noop:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any, **kwargs: Any) -> _Noop:
            return self

        def inc(self, *args: Any, **kwargs: Any) -> None:
            pass

        def dec(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set(self, *args: Any, **kwargs: Any) -> None:
            pass

        def observe(self, *args: Any, **kwargs: Any) -> None:
            pass

    Counter = Gauge = Histogram = _Noop  # type: ignore[assignment,misc]
    CollectorRegistry = object  # type: ignore[assignment,misc]

    def generate_latest(*args: Any, **kwargs: Any) -> bytes:  # type: ignore[misc]
        return b"# prometheus_client is not installed\n"


REGISTRY = CollectorRegistry() if PROMETHEUS_AVAILABLE else None

_kwargs = {"registry": REGISTRY} if PROMETHEUS_AVAILABLE else {}

# --------------------------------------------------------------------------- #
# Pipeline metrics
# --------------------------------------------------------------------------- #
EVENTS_INGESTED = Counter(
    "signalforge_events_ingested_total",
    "Raw log records accepted by a collector.",
    ["source", "tenant"],
    **_kwargs,
)
EVENTS_NORMALIZED = Counter(
    "signalforge_events_normalized_total",
    "Records successfully mapped to OCSF.",
    ["source", "class_name"],
    **_kwargs,
)
NORMALIZATION_FAILURES = Counter(
    "signalforge_normalization_failures_total",
    "Records routed to the dead-letter topic.",
    ["source", "reason"],
    **_kwargs,
)
EVENTS_INDEXED = Counter(
    "signalforge_events_indexed_total",
    "Events written to the security event store.",
    ["outcome"],
    **_kwargs,
)
ALERTS_EMITTED = Counter(
    "signalforge_alerts_total",
    "Alerts produced by the detection engine.",
    ["rule_id", "level", "risk_level"],
    **_kwargs,
)
ALERTS_SUPPRESSED = Counter(
    "signalforge_alerts_suppressed_total",
    "Alerts suppressed by behavioural context or dedup.",
    ["rule_id", "reason"],
    **_kwargs,
)
CORRELATIONS = Counter(
    "signalforge_correlations_total",
    "Correlation rules satisfied.",
    ["correlation_id", "scenario"],
    **_kwargs,
)
INCIDENTS = Counter(
    "signalforge_incidents_total",
    "Incidents opened or updated.",
    ["action", "severity"],
    **_kwargs,
)
RESPONSE_ACTIONS = Counter(
    "signalforge_response_actions_total",
    "Response playbook lifecycle transitions.",
    ["playbook", "status"],
    **_kwargs,
)
INTEL_LOOKUPS = Counter(
    "signalforge_intel_lookups_total",
    "Threat-intel lookups by provider and cache outcome.",
    ["provider", "cache"],
    **_kwargs,
)

DETECTION_LATENCY = Histogram(
    "signalforge_detection_latency_seconds",
    "Time to evaluate one event against the rule set.",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    **_kwargs,
)
END_TO_END_LATENCY = Histogram(
    "signalforge_end_to_end_latency_seconds",
    "Time from log receipt to alert emission.",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    **_kwargs,
)
INDEX_LATENCY = Histogram(
    "signalforge_index_latency_seconds",
    "Bulk write latency to the security event store.",
    buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    **_kwargs,
)
API_LATENCY = Histogram(
    "signalforge_api_request_seconds",
    "HTTP request latency.",
    ["method", "route", "status"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    **_kwargs,
)

CONSUMER_LAG = Gauge(
    "signalforge_consumer_lag",
    "Uncommitted records per consumer group.",
    ["group", "topic"],
    **_kwargs,
)
WINDOWS_OPEN = Gauge(
    "signalforge_windows_open",
    "Sliding windows currently held in memory.",
    ["engine"],
    **_kwargs,
)
SPOOLED_EVENTS = Gauge(
    "signalforge_spooled_events",
    "Events parked on disk because the event store was unreachable.",
    **_kwargs,
)
RULES_LOADED = Gauge(
    "signalforge_rules_loaded",
    "Rules currently loaded, by kind.",
    ["kind"],
    **_kwargs,
)


def render_metrics() -> bytes:
    if not PROMETHEUS_AVAILABLE:
        return generate_latest()
    return generate_latest(REGISTRY)


@contextmanager
def observe(histogram: Any, **labels: str) -> Iterator[None]:
    """Time a block into a histogram."""
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - started
        target = histogram.labels(**labels) if labels else histogram
        target.observe(elapsed)


def record_alert_metrics(alert: Any) -> None:
    ALERTS_EMITTED.labels(
        rule_id=alert.rule_id, level=alert.rule_level, risk_level=alert.risk_level
    ).inc()


def record_pipeline_metrics(result: Any) -> None:
    """Reflect a :class:`signalforge.pipeline.PipelineResult` in the metrics."""
    for event in getattr(result, "events", []):
        EVENTS_NORMALIZED.labels(
            source=event.sf_source or "unknown", class_name=event.class_name or "unknown"
        ).inc()
    for alert in getattr(result, "alerts", []):
        record_alert_metrics(alert)
    for hit in getattr(result, "hits", []):
        CORRELATIONS.labels(correlation_id=hit.correlation.id, scenario=hit.scenario).inc()
    for incident in getattr(result, "incidents", []):
        INCIDENTS.labels(action="upserted", severity=str(incident.severity.value)).inc()
    for record, reason in getattr(result, "dlq", []):
        NORMALIZATION_FAILURES.labels(source=record.source, reason=reason.split(":")[0][:40]).inc()
    index_result = getattr(result, "index_result", None)
    if index_result is not None:
        EVENTS_INDEXED.labels(outcome="indexed").inc(index_result.indexed)
        EVENTS_INDEXED.labels(outcome="duplicate").inc(index_result.duplicates)
        if index_result.spooled:
            EVENTS_INDEXED.labels(outcome="spooled").inc(index_result.spooled)


# --------------------------------------------------------------------------- #
# Tracing
# --------------------------------------------------------------------------- #
def setup_tracing(service_name: str, settings: Optional[Settings] = None) -> bool:
    """Wire up OTLP tracing when enabled.  Returns True when active."""
    settings = settings or get_settings()
    if not settings.otel_enabled:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("OpenTelemetry requested but the SDK is not installed")
        return False

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "deployment.environment": settings.environment,
            }
        )
    )
    endpoint = settings.otel_exporter_endpoint or "http://localhost:4318/v1/traces"
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    log.info("tracing enabled", extra={"service": service_name, "endpoint": endpoint})
    return True


def get_tracer(name: str = "signalforge") -> Any:
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except ImportError:  # pragma: no cover

        class _NoopTracer:
            @contextmanager
            def start_as_current_span(self, *args: Any, **kwargs: Any) -> Iterator[None]:
                yield

        return _NoopTracer()


def snapshot(pipeline: Any) -> Dict[str, Any]:
    """Reflect engine gauges and return a JSON-friendly stats blob."""
    stats = pipeline.stats if hasattr(pipeline, "stats") else {}
    detection = stats.get("detection", {})
    correlation = stats.get("correlation", {})
    WINDOWS_OPEN.labels(engine="detection").set(detection.get("windows_open", 0))
    WINDOWS_OPEN.labels(engine="correlation").set(correlation.get("windows_open", 0))
    RULES_LOADED.labels(kind="detection").set(stats.get("rules", 0))
    RULES_LOADED.labels(kind="correlation").set(stats.get("correlations", 0))
    return stats
