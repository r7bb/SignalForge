"""Security-event store.

Two interchangeable backends behind one interface:

* ``OpenSearchEventStore`` - production path.  Writes are idempotent because the
  document ``_id`` is the event's content hash (``sf_dedup_key``), so
  at-least-once delivery from the bus can never create duplicate events.
  Failed bulk writes are retried with exponential backoff and, if the cluster
  is still unreachable, parked in an on-disk spool instead of being dropped.
* ``InMemoryEventStore`` - same semantics for tests and laptop demos.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config import Settings, get_settings
from ..models.ocsf import OcsfEvent

log = logging.getLogger("signalforge.storage.events")


@dataclass
class IndexResult:
    indexed: int = 0
    duplicates: int = 0
    spooled: int = 0
    failed: int = 0
    attempts: int = 1

    @property
    def accepted(self) -> int:
        """Events that are safe (written or durably spooled for retry)."""
        return self.indexed + self.duplicates + self.spooled


@dataclass
class EventQuery:
    tenant: Optional[str] = None
    text: Optional[str] = None
    class_uids: Sequence[int] = ()
    principal: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    session_uid: Optional[str] = None
    status_id: Optional[int] = None
    min_severity_id: Optional[int] = None
    event_ids: Sequence[str] = ()
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    size: int = 50
    offset: int = 0
    ascending: bool = False

    def to_opensearch(self) -> Dict[str, Any]:
        filters: List[Dict[str, Any]] = []
        if self.tenant:
            filters.append({"term": {"sf_tenant": self.tenant}})
        if self.class_uids:
            filters.append({"terms": {"class_uid": list(self.class_uids)}})
        if self.principal:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {
                                "term": {
                                    "actor.user.name": {
                                        "value": self.principal,
                                        "case_insensitive": True,
                                    }
                                }
                            },
                            {
                                "term": {
                                    "actor.user.email_addr": {
                                        "value": self.principal,
                                        "case_insensitive": True,
                                    }
                                }
                            },
                            {
                                "term": {
                                    "user.name": {"value": self.principal, "case_insensitive": True}
                                }
                            },
                            {
                                "term": {
                                    "user.email_addr": {
                                        "value": self.principal,
                                        "case_insensitive": True,
                                    }
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )
        if self.source_ip:
            filters.append({"term": {"src_endpoint.ip": self.source_ip}})
        if self.hostname:
            filters.append(
                {"term": {"device.hostname": {"value": self.hostname, "case_insensitive": True}}}
            )
        if self.session_uid:
            filters.append({"term": {"actor.session.uid": self.session_uid}})
        if self.status_id is not None:
            filters.append({"term": {"status_id": self.status_id}})
        if self.min_severity_id is not None:
            filters.append({"range": {"severity_id": {"gte": self.min_severity_id}}})
        if self.event_ids:
            filters.append({"terms": {"sf_event_id": list(self.event_ids)}})
        if self.start or self.end:
            time_range: Dict[str, Any] = {}
            if self.start:
                time_range["gte"] = self.start.isoformat()
            if self.end:
                time_range["lte"] = self.end.isoformat()
            filters.append({"range": {"time": time_range}})
        query: Dict[str, Any] = {"bool": {"filter": filters}}
        if self.text:
            query["bool"]["must"] = [
                {"query_string": {"query": self.text, "fields": ["*"], "analyze_wildcard": True}}
            ]
        return {
            "size": self.size,
            "from": self.offset,
            "query": query,
            "sort": [{"time": {"order": "asc" if self.ascending else "desc"}}],
        }


@dataclass
class SearchResult:
    total: int = 0
    events: List[OcsfEvent] = field(default_factory=list)
    took_ms: int = 0


class EventStore:
    """Interface implemented by both backends."""

    def index(self, events: Sequence[OcsfEvent]) -> IndexResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def search(self, query: EventQuery) -> SearchResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def raw_search(self, body: Dict[str, Any], tenant: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def get(self, event_id: str, tenant: Optional[str] = None) -> Optional[OcsfEvent]:
        result = self.search(EventQuery(tenant=tenant, event_ids=[event_id], size=1))
        return result.events[0] if result.events else None

    def count(self, query: EventQuery) -> int:
        return self.search(EventQuery(**{**query.__dict__, "size": 0})).total

    def timeline(
        self,
        tenant: str,
        *,
        principals: Sequence[str] = (),
        source_ips: Sequence[str] = (),
        hostnames: Sequence[str] = (),
        session_uids: Sequence[str] = (),
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        size: int = 200,
    ) -> List[OcsfEvent]:
        """Every event touching any of the given entities, ordered by time."""
        collected: Dict[str, OcsfEvent] = {}
        probes: List[EventQuery] = []
        for principal in principals:
            probes.append(
                EventQuery(
                    tenant=tenant,
                    principal=principal,
                    start=start,
                    end=end,
                    size=size,
                    ascending=True,
                )
            )
        for ip in source_ips:
            probes.append(
                EventQuery(
                    tenant=tenant, source_ip=ip, start=start, end=end, size=size, ascending=True
                )
            )
        for host in hostnames:
            probes.append(
                EventQuery(
                    tenant=tenant, hostname=host, start=start, end=end, size=size, ascending=True
                )
            )
        for session in session_uids:
            probes.append(
                EventQuery(
                    tenant=tenant,
                    session_uid=session,
                    start=start,
                    end=end,
                    size=size,
                    ascending=True,
                )
            )
        for probe in probes:
            for event in self.search(probe).events:
                collected[event.sf_event_id] = event
        # Out-of-order arrival is normal; the timeline is always sorted by
        # event time (not ingest time) and ties broken by ingest order.
        return sorted(collected.values(), key=lambda e: (e.time, e.sf_ingested_at))[:size]

    def stats(
        self, tenant: Optional[str] = None, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def flush_spool(self) -> IndexResult:
        return IndexResult()

    def close(self) -> None:
        return None


# --------------------------------------------------------------------------- #
# In-memory backend
# --------------------------------------------------------------------------- #
class InMemoryEventStore(EventStore):
    def __init__(self) -> None:
        self._by_dedup: Dict[Tuple[str, str], OcsfEvent] = {}
        self._lock = threading.RLock()

    # -- writes ------------------------------------------------------------
    def index(self, events: Sequence[OcsfEvent]) -> IndexResult:
        result = IndexResult()
        with self._lock:
            for event in events:
                key = (event.sf_tenant, event.sf_dedup_key or event.compute_dedup_key())
                if key in self._by_dedup:
                    result.duplicates += 1
                    continue
                self._by_dedup[key] = event
                result.indexed += 1
        return result

    # -- reads -------------------------------------------------------------
    def _all(self, tenant: Optional[str]) -> List[OcsfEvent]:
        with self._lock:
            return [
                event
                for (event_tenant, _), event in self._by_dedup.items()
                if tenant is None or event_tenant == tenant
            ]

    def search(self, query: EventQuery) -> SearchResult:
        started = time.perf_counter()
        matches = [event for event in self._all(query.tenant) if self._matches(event, query)]
        matches.sort(key=lambda e: (e.time, e.sf_ingested_at), reverse=not query.ascending)
        window = matches[query.offset : query.offset + query.size] if query.size else []
        return SearchResult(
            total=len(matches),
            events=window,
            took_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _matches(event: OcsfEvent, query: EventQuery) -> bool:
        if query.class_uids and event.class_uid not in query.class_uids:
            return False
        if query.principal:
            needle = query.principal.lower()
            candidates = {
                (event.principal or "").lower(),
                (event.target_principal or "").lower(),
            }
            if needle not in candidates:
                return False
        if query.source_ip and event.source_ip != query.source_ip:
            return False
        if query.hostname and (event.hostname or "").lower() != query.hostname.lower():
            return False
        if query.session_uid and event.session_uid != query.session_uid:
            return False
        if query.status_id is not None and event.status_id != query.status_id:
            return False
        if query.min_severity_id is not None and event.severity_id < query.min_severity_id:
            return False
        if query.event_ids and event.sf_event_id not in query.event_ids:
            return False
        if query.start and event.time < query.start:
            return False
        if query.end and event.time > query.end:
            return False
        if query.text:
            haystack = json.dumps(event.to_document(), default=str).lower()
            needle = query.text.strip("*").lower()
            if needle not in haystack:
                return False
        return True

    def raw_search(self, body: Dict[str, Any], tenant: Optional[str] = None) -> Dict[str, Any]:
        """Minimal DSL support so retro-hunts work without a cluster.

        Only the constructs the Sigma backend emits are honoured; the streaming
        evaluator remains the source of truth for rule semantics.
        """
        from .memory_dsl import execute_dsl  # local import to avoid a cycle

        return execute_dsl(body, self._all(tenant))

    def stats(
        self, tenant: Optional[str] = None, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        events = self._all(tenant)
        if since:
            events = [event for event in events if event.time >= since]
        by_class: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for event in events:
            by_class[event.class_name or str(event.class_uid)] = (
                by_class.get(event.class_name or str(event.class_uid), 0) + 1
            )
            by_severity[event.severity or "Unknown"] = (
                by_severity.get(event.severity or "Unknown", 0) + 1
            )
        return {
            "total": len(events),
            "by_class": by_class,
            "by_severity": by_severity,
            "backend": "memory",
        }

    def clear(self) -> None:
        with self._lock:
            self._by_dedup.clear()


# --------------------------------------------------------------------------- #
# OpenSearch backend
# --------------------------------------------------------------------------- #
INDEX_TEMPLATE: Dict[str, Any] = {
    "index_patterns": ["sf-events-*"],
    "template": {
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "1s",
                "mapping": {"total_fields": {"limit": 4000}},
            }
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {"type": "keyword", "ignore_above": 4096},
                    }
                }
            ],
            "properties": {
                "time": {"type": "date"},
                "start_time": {"type": "date"},
                "end_time": {"type": "date"},
                "sf_ingested_at": {"type": "date"},
                "class_uid": {"type": "integer"},
                "category_uid": {"type": "integer"},
                "activity_id": {"type": "integer"},
                "type_uid": {"type": "integer"},
                "status_id": {"type": "integer"},
                "severity_id": {"type": "integer"},
                "sf_risk_score": {"type": "integer"},
                "sf_tenant": {"type": "keyword"},
                "sf_event_id": {"type": "keyword"},
                "sf_dedup_key": {"type": "keyword"},
                "message": {"type": "text"},
                "src_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                "dst_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                "device": {"properties": {"ip": {"type": "ip"}}},
                "http_response": {"properties": {"code": {"type": "integer"}}},
                "unmapped": {"type": "object", "enabled": True},
            },
        },
    },
    "priority": 200,
}


class OpenSearchEventStore(EventStore):
    """OpenSearch-backed store with retry, backoff and an on-disk spool."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        client: Any = None,
        *,
        spool_path: Optional[str] = None,
        max_attempts: int = 4,
        base_backoff: float = 0.25,
    ) -> None:
        self.settings = settings or get_settings()
        self.max_attempts = max_attempts
        self.base_backoff = base_backoff
        self.spool_path = Path(spool_path or "var/spool/events.ndjson")
        self._client = client
        self._template_ready = False

    # -- client ------------------------------------------------------------
    @property
    def client(self) -> Any:
        if self._client is None:
            from opensearchpy import OpenSearch  # imported lazily

            auth = None
            if self.settings.opensearch_user:
                auth = (self.settings.opensearch_user, self.settings.opensearch_password or "")
            self._client = OpenSearch(
                hosts=[self.settings.opensearch_url],
                http_auth=auth,
                verify_certs=self.settings.opensearch_verify_certs,
                ssl_show_warn=False,
                timeout=self.settings.opensearch_request_timeout,
            )
        return self._client

    def index_name(self, event: OcsfEvent) -> str:
        return "%s-%s" % (self.settings.opensearch_index_prefix, event.time.strftime("%Y.%m.%d"))

    def ensure_template(self) -> None:
        if self._template_ready:
            return
        try:
            self.client.indices.put_index_template(
                name="%s-template" % self.settings.opensearch_index_prefix, body=INDEX_TEMPLATE
            )
            self._template_ready = True
        except Exception as exc:  # cluster may not be up yet; writes will retry
            log.warning("index template not applied", extra={"error": str(exc)})

    # -- writes ------------------------------------------------------------
    def index(self, events: Sequence[OcsfEvent]) -> IndexResult:
        if not events:
            return IndexResult()
        self.ensure_template()
        result = IndexResult()
        pending = list(events)
        for attempt in range(1, self.max_attempts + 1):
            result.attempts = attempt
            try:
                indexed, duplicates, retryable = self._bulk(pending)
            except Exception as exc:
                log.warning(
                    "bulk write failed",
                    extra={"attempt": attempt, "events": len(pending), "error": str(exc)},
                )
                retryable = pending
                indexed = duplicates = 0
            result.indexed += indexed
            result.duplicates += duplicates
            if not retryable:
                return result
            pending = retryable
            if attempt < self.max_attempts:
                time.sleep(self._backoff(attempt))
        # Still failing: spool to disk so the events are never lost.
        result.spooled = self._spool(pending)
        return result

    def _bulk(self, events: Sequence[OcsfEvent]) -> Tuple[int, int, List[OcsfEvent]]:
        lines: List[str] = []
        for event in events:
            lines.append(
                json.dumps(
                    {
                        "index": {
                            "_index": self.index_name(event),
                            # Content hash as _id makes re-delivery a no-op overwrite.
                            "_id": event.sf_dedup_key or event.compute_dedup_key(),
                        }
                    }
                )
            )
            lines.append(json.dumps(event.to_document(), default=str))
        response = self.client.bulk(body="\n".join(lines) + "\n", refresh=False)
        indexed = duplicates = 0
        retryable: List[OcsfEvent] = []
        for event, item in zip(events, response.get("items", [])):
            outcome = item.get("index", {})
            status = outcome.get("status", 500)
            if status in (200, 201):
                # An overwrite ("updated") means the same content hash was
                # already stored - i.e. a re-delivered duplicate.
                if outcome.get("result") == "updated":
                    duplicates += 1
                else:
                    indexed += 1
            elif status in (429, 502, 503, 504):
                retryable.append(event)
            else:
                log.error("event rejected", extra={"status": status, "error": outcome.get("error")})
        return indexed, duplicates, retryable

    def _backoff(self, attempt: int) -> float:
        # Exponential backoff with jitter so parallel workers do not sync up.
        return self.base_backoff * (2 ** (attempt - 1)) * (0.5 + random.random())

    def _spool(self, events: Sequence[OcsfEvent]) -> int:
        self.spool_path.parent.mkdir(parents=True, exist_ok=True)
        with self.spool_path.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event.to_document(), default=str) + "\n")
        log.error(
            "events spooled for retry", extra={"count": len(events), "path": str(self.spool_path)}
        )
        return len(events)

    def flush_spool(self) -> IndexResult:
        """Re-send everything parked on disk.  Safe to call repeatedly."""
        if not self.spool_path.exists():
            return IndexResult()
        with self.spool_path.open("r", encoding="utf-8") as handle:
            events = [OcsfEvent.model_validate(json.loads(line)) for line in handle if line.strip()]
        if not events:
            return IndexResult()
        working = self.spool_path.with_suffix(".inflight")
        self.spool_path.rename(working)
        result = self.index(events)
        if result.spooled:
            working.unlink(missing_ok=True)
        else:
            working.unlink(missing_ok=True)
        return result

    @property
    def spooled_count(self) -> int:
        if not self.spool_path.exists():
            return 0
        with self.spool_path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    # -- reads -------------------------------------------------------------
    def search(self, query: EventQuery) -> SearchResult:
        body = query.to_opensearch()
        response = self.raw_search(body)
        hits = response.get("hits", {})
        total = hits.get("total", {})
        return SearchResult(
            total=total.get("value", 0) if isinstance(total, dict) else int(total or 0),
            events=[OcsfEvent.model_validate(hit["_source"]) for hit in hits.get("hits", [])],
            took_ms=response.get("took", 0),
        )

    def raw_search(self, body: Dict[str, Any], tenant: Optional[str] = None) -> Dict[str, Any]:
        if tenant:
            body = dict(body)
            query = body.setdefault("query", {"bool": {"filter": []}})
            query.setdefault("bool", {}).setdefault("filter", []).append(
                {"term": {"sf_tenant": tenant}}
            )
        return self.client.search(index="%s-*" % self.settings.opensearch_index_prefix, body=body)

    def stats(
        self, tenant: Optional[str] = None, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"filter": []}},
            "aggs": {
                "by_class": {"terms": {"field": "class_name", "size": 20}},
                "by_severity": {"terms": {"field": "severity", "size": 10}},
            },
        }
        if tenant:
            body["query"]["bool"]["filter"].append({"term": {"sf_tenant": tenant}})
        if since:
            body["query"]["bool"]["filter"].append({"range": {"time": {"gte": since.isoformat()}}})
        try:
            response = self.raw_search(body)
        except Exception as exc:
            log.warning("stats query failed", extra={"error": str(exc)})
            return {
                "total": 0,
                "by_class": {},
                "by_severity": {},
                "backend": "opensearch",
                "degraded": True,
            }
        aggregations = response.get("aggregations", {})
        return {
            "total": response.get("hits", {}).get("total", {}).get("value", 0),
            "by_class": {
                b["key"]: b["doc_count"]
                for b in aggregations.get("by_class", {}).get("buckets", [])
            },
            "by_severity": {
                b["key"]: b["doc_count"]
                for b in aggregations.get("by_severity", {}).get("buckets", [])
            },
            "backend": "opensearch",
        }

    def close(self) -> None:
        if self._client is not None and hasattr(self._client, "close"):
            self._client.close()


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
_STORE: Optional[EventStore] = None


def get_event_store(settings: Optional[Settings] = None, *, refresh: bool = False) -> EventStore:
    global _STORE
    if _STORE is not None and not refresh:
        return _STORE
    settings = settings or get_settings()
    _STORE = OpenSearchEventStore(settings) if settings.use_opensearch else InMemoryEventStore()
    return _STORE


def reset_event_store() -> None:
    global _STORE
    if _STORE is not None:
        _STORE.close()
    _STORE = None
