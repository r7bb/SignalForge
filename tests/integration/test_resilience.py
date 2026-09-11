"""Failure handling: bus redelivery, store outages, enrichment degradation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest
from signalforge.enrich import (
    VERDICT_DEGRADED,
    VERDICT_MALICIOUS,
    HttpFeedProvider,
    InMemoryCache,
    StaticFeedProvider,
    ThreatIntelService,
)
from signalforge.enrich.intel import InternalClassifier, Provider
from signalforge.models.ocsf import OcsfEvent, RawLogRecord
from signalforge.normalize import normalize
from signalforge.storage.bus import InMemoryBus
from signalforge.storage.events import OpenSearchEventStore

pytestmark = pytest.mark.integration

BASE = datetime(2026, 9, 10, 13, 40, tzinfo=timezone.utc)


def sample_events(count: int = 3) -> List[OcsfEvent]:
    return [
        normalize(
            RawLogRecord(
                source="linux.sshd",
                tenant="acme",
                raw="Sep 10 13:4%d:0%d web-01 sshd[%d]: Failed password for alex "
                "from 10.0.4.82 port %d ssh2" % (index % 10, index % 10, index, 40000 + index),
            )
        )
        for index in range(count)
    ]


# ----------------------------------------------------------------- the bus ---
def test_consumer_crash_replays_the_uncommitted_batch() -> None:
    async def scenario() -> Dict[str, Any]:
        bus = InMemoryBus()
        for index in range(10):
            await bus.publish("sf.logs.raw", {"n": index}, key="k%d" % index)

        first = bus.consumer(["sf.logs.raw"], "normalizer")
        batch = await first.poll(max_records=4)
        # Crash before committing.
        await first.close()

        second = bus.consumer(["sf.logs.raw"], "normalizer")
        replayed = await second.poll(max_records=4)
        await second.commit()
        following = await second.poll(max_records=4)
        return {
            "batch": [record.value["n"] for record in batch],
            "replayed": [record.value["n"] for record in replayed],
            "following": [record.value["n"] for record in following],
            "lag": second.lag,
        }

    outcome = asyncio.run(scenario())
    assert outcome["batch"] == [0, 1, 2, 3]
    assert outcome["replayed"] == [0, 1, 2, 3], "nothing may be skipped after a crash"
    assert outcome["following"] == [4, 5, 6, 7]
    # Lag is measured against the *committed* offset (4), so the in-flight
    # batch 4-7 still counts as lag until it is committed.
    assert outcome["lag"] == 6


def test_consumer_groups_are_independent() -> None:
    async def scenario() -> List[int]:
        bus = InMemoryBus()
        for index in range(5):
            await bus.publish("sf.alerts", {"n": index})
        correlator = bus.consumer(["sf.alerts"], "correlator")
        await correlator.poll(5)
        await correlator.commit()
        enricher = bus.consumer(["sf.alerts"], "enricher")
        return [record.value["n"] for record in await enricher.poll(5)]

    assert asyncio.run(scenario()) == [0, 1, 2, 3, 4]


def test_dead_letter_topic_receives_rejected_records() -> None:
    async def scenario() -> int:
        bus = InMemoryBus()
        await bus.publish("sf.dlq", {"reason": "no mapper", "source": "windows.security"})
        return bus.depth("sf.dlq")

    assert asyncio.run(scenario()) == 1


# --------------------------------------------------------- the event store ---
class FlakyClient:
    """Fails the first ``failures`` bulk calls, then succeeds."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0
        self.documents: Dict[str, Dict[str, Any]] = {}
        self.indices = self

    def put_index_template(self, **_: Any) -> Dict[str, Any]:
        return {"acknowledged": True}

    def bulk(self, body: str, **_: Any) -> Dict[str, Any]:
        import json

        self.calls += 1
        if self.calls <= self.failures:
            raise ConnectionError("cluster unavailable")
        lines = [line for line in body.splitlines() if line.strip()]
        items = []
        for index in range(0, len(lines), 2):
            action = json.loads(lines[index])["index"]
            document = json.loads(lines[index + 1])
            existed = action["_id"] in self.documents
            self.documents[action["_id"]] = document
            items.append(
                {
                    "index": {
                        "status": 200 if existed else 201,
                        "result": "updated" if existed else "created",
                    }
                }
            )
        return {"items": items, "errors": False}


def test_transient_store_failure_is_retried(tmp_path) -> None:
    client = FlakyClient(failures=2)
    store = OpenSearchEventStore(
        client=client,
        spool_path=str(tmp_path / "spool.ndjson"),
        max_attempts=4,
        base_backoff=0.001,
    )
    result = store.index(sample_events(3))
    assert result.indexed == 3
    assert result.spooled == 0
    assert result.attempts >= 3


def test_persistent_store_failure_spools_instead_of_dropping(tmp_path) -> None:
    client = FlakyClient(failures=99)
    spool = tmp_path / "spool.ndjson"
    store = OpenSearchEventStore(
        client=client,
        spool_path=str(spool),
        max_attempts=2,
        base_backoff=0.001,
    )
    events = sample_events(4)
    result = store.index(events)

    assert result.indexed == 0
    assert result.spooled == 4
    assert result.accepted == 4, "spooled events are accounted for, not lost"
    assert spool.exists()
    assert store.spooled_count == 4

    # Once the cluster recovers, the spool drains.
    client.failures = 0
    flushed = store.flush_spool()
    assert flushed.indexed == 4
    assert store.spooled_count == 0


def test_duplicate_writes_are_reported_as_duplicates(tmp_path) -> None:
    client = FlakyClient(failures=0)
    store = OpenSearchEventStore(
        client=client, spool_path=str(tmp_path / "spool.ndjson"), base_backoff=0.001
    )
    events = sample_events(3)
    assert store.index(events).indexed == 3
    second = store.index(events)
    assert second.duplicates == 3
    assert second.indexed == 0
    assert len(client.documents) == 3


# ------------------------------------------------------------- enrichment ---
class ExplodingProvider(Provider):
    name = "exploding"

    def lookup(self, value: str, type_: str):
        raise RuntimeError("provider is on fire")


def test_provider_exception_does_not_break_enrichment() -> None:
    service = ThreatIntelService(
        cache=InMemoryCache(),
        providers=[ExplodingProvider(), InternalClassifier(["10.0.0.0/8"])],
    )
    report = service.lookup("10.0.4.82", "ip")
    assert report.is_internal is True
    assert "exploding" not in report.providers


def test_static_feed_recognises_known_indicators() -> None:
    service = ThreatIntelService(
        cache=InMemoryCache(),
        providers=[
            InternalClassifier(["10.0.0.0/8"]),
            StaticFeedProvider("schemas/intel/static_feed.json"),
        ],
    )
    malicious = service.lookup("203.0.113.66", "ip")
    assert malicious.verdict == VERDICT_MALICIOUS
    assert malicious.score >= 80

    tor = service.lookup("185.220.101.7", "ip")
    assert tor.verdict == "anonymizer"
    assert "tor-exit" in tor.categories

    internal = service.lookup("10.0.4.82", "ip")
    assert internal.is_internal is True


def test_lookups_are_cached() -> None:
    cache = InMemoryCache()
    service = ThreatIntelService(
        cache=cache, providers=[StaticFeedProvider("schemas/intel/static_feed.json")]
    )
    first = service.lookup("203.0.113.66", "ip")
    second = service.lookup("203.0.113.66", "ip")
    assert first.cached is False
    assert second.cached is True
    assert cache.stats["hits"] >= 1


def test_http_provider_retries_then_opens_its_circuit(monkeypatch) -> None:
    calls = {"count": 0}

    class Response:
        status_code = 503

        def json(self) -> Dict[str, Any]:
            return {}

        def raise_for_status(self) -> None:
            raise RuntimeError("503")

    def fake_get(*args: Any, **kwargs: Any) -> Response:
        calls["count"] += 1
        return Response()

    import httpx

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr("time.sleep", lambda *_: None)

    provider = HttpFeedProvider(
        "https://intel.example.org/lookup",
        max_attempts=3,
        failure_threshold=2,
        cooldown_seconds=60,
    )
    first = provider.lookup("203.0.113.66", "ip")
    assert first["verdict"] == VERDICT_DEGRADED
    assert calls["count"] == 3, "each attempt is retried before giving up"

    provider.lookup("203.0.113.67", "ip")
    assert provider.circuit_open, "repeated failures must trip the breaker"

    before = calls["count"]
    third = provider.lookup("203.0.113.68", "ip")
    assert third["verdict"] == VERDICT_DEGRADED
    assert calls["count"] == before, "an open circuit must not call the provider"


def test_enrichment_attaches_to_the_event() -> None:
    service = ThreatIntelService(
        cache=InMemoryCache(),
        providers=[
            InternalClassifier(["10.0.0.0/8"]),
            StaticFeedProvider("schemas/intel/static_feed.json"),
        ],
    )
    event = normalize(
        RawLogRecord(
            source="linux.sshd",
            tenant="acme",
            raw="Sep 10 13:41:02 web-01 sshd[1]: Failed password for alex from 185.220.101.7 port 1 ssh2",
        )
    )
    enrichments = service.enrich_event(event)
    assert enrichments
    assert any(enrichment.value == "anonymizer" for enrichment in event.enrichments)
