"""TTL cache for enrichment lookups (Redis when configured, in-process otherwise).

Enrichment is the one part of the pipeline that talks to the outside world, so
every lookup goes through here: the same indicator seen a thousand times in a
minute costs one request.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

from ..config import Settings, get_settings

log = logging.getLogger("signalforge.enrich.cache")


class Cache:
    def get(self, key: str) -> Optional[Dict[str, Any]]:  # pragma: no cover - abstract
        raise NotImplementedError

    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        raise NotImplementedError

    def clear(self) -> None:
        return None

    @property
    def stats(self) -> Dict[str, int]:
        return {}


class InMemoryCache(Cache):
    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 50_000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._hits = 0
        self._misses = 0
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, value = entry
            if expires_at < time.time():
                del self._entries[key]
                self._misses += 1
                return None
            self._hits += 1
            return value

    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        with self._lock:
            if len(self._entries) >= self.max_entries:
                # Drop the soonest-to-expire entries first.
                for stale, _ in sorted(self._entries.items(), key=lambda kv: kv[1][0])[:100]:
                    self._entries.pop(stale, None)
            self._entries[key] = (time.time() + (ttl or self.ttl_seconds), value)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._hits = self._misses = 0

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses, "size": len(self._entries)}


class RedisCache(Cache):
    def __init__(self, url: str, ttl_seconds: int = 3600, namespace: str = "sf:intel") -> None:
        self.url = url
        self.ttl_seconds = ttl_seconds
        self.namespace = namespace
        self._client: Any = None
        self._hits = 0
        self._misses = 0

    @property
    def client(self) -> Any:
        if self._client is None:
            import redis

            self._client = redis.Redis.from_url(self.url, decode_responses=True)
        return self._client

    def _key(self, key: str) -> str:
        return "%s:%s" % (self.namespace, key)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            raw = self.client.get(self._key(key))
        except Exception as exc:  # cache problems must never break enrichment
            log.warning("redis get failed", extra={"error": str(exc)})
            return None
        if raw is None:
            self._misses += 1
            return None
        self._hits += 1
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        try:
            self.client.setex(
                self._key(key), ttl or self.ttl_seconds, json.dumps(value, default=str)
            )
        except Exception as exc:
            log.warning("redis set failed", extra={"error": str(exc)})

    def clear(self) -> None:
        try:
            for key in self.client.scan_iter("%s:*" % self.namespace):
                self.client.delete(key)
        except Exception as exc:
            log.warning("redis clear failed", extra={"error": str(exc)})

    @property
    def stats(self) -> Dict[str, int]:
        return {"hits": self._hits, "misses": self._misses}


def get_cache(settings: Optional[Settings] = None) -> Cache:
    settings = settings or get_settings()
    if settings.redis_url:
        return RedisCache(settings.redis_url, settings.intel_cache_ttl_seconds)
    return InMemoryCache(settings.intel_cache_ttl_seconds)
