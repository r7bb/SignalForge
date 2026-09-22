"""Who else is looking at this incident right now.

Optimistic concurrency already stops a stale write, but it tells the analyst
*after* they have typed. Presence is the cheap preventative half: seeing "Dana
is viewing this" before starting avoids the collision that the ``409`` would
otherwise report.

Deliberately **not** in the database. Presence is worthless thirty seconds
later, so it belongs in something with expiry: Redis when configured, an
in-process dict otherwise. Writing a row per heartbeat would turn a cosmetic
feature into write load on the incident table.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("signalforge.presence")

#: How long a heartbeat counts for. The dashboard re-announces well inside
#: this, so a closed tab disappears within half a minute rather than lingering
#: as a phantom viewer.
DEFAULT_TTL_SECONDS = 30


@dataclass(frozen=True)
class Viewer:
    email: str
    user_id: str
    #: Seconds since their last heartbeat.
    idle_seconds: int

    def to_dict(self) -> Dict[str, Any]:
        return {"email": self.email, "user_id": self.user_id, "idle_seconds": self.idle_seconds}


class PresenceTracker:
    """Short-lived "who is here" state.

    Backed by Redis when a URL is configured so every API replica sees the same
    viewers; otherwise in-process, which is correct for a single process and
    honest about its limits in a multi-replica deployment (noted in the
    roadmap).
    """

    def __init__(self, settings: Any = None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        from ..config import get_settings

        self.settings = settings or get_settings()
        self.ttl = ttl_seconds
        self._local: Dict[str, Dict[str, Tuple[str, float]]] = {}
        self._lock = threading.Lock()
        self._redis = self._connect()

    def _connect(self) -> Optional[Any]:
        url = getattr(self.settings, "redis_url", None)
        if not url:
            return None
        try:
            import redis

            client = redis.Redis.from_url(url, decode_responses=True)
            client.ping()
            logger.info("presence backed by redis")
            return client
        except Exception as exc:
            # A presence feature must never stop the API serving incidents.
            logger.warning("presence falling back to in-process", extra={"error": str(exc)})
            return None

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"

    def _key(self, tenant: str, incident_key: str) -> str:
        return "sf:presence:%s:%s" % (tenant, incident_key)

    # ------------------------------------------------------------------ #
    def announce(self, tenant: str, incident_key: str, *, email: str, user_id: str) -> None:
        """Record a heartbeat from one viewer."""
        key = self._key(tenant, incident_key)
        now = time.time()
        if self._redis is not None:
            try:
                self._redis.hset(key, email, "%s|%f" % (user_id, now))
                # Refreshed on every heartbeat, so the whole hash disappears
                # once the last viewer stops announcing.
                self._redis.expire(key, self.ttl * 2)
                return
            except Exception as exc:  # pragma: no cover - network
                logger.warning("presence write failed", extra={"error": str(exc)})
        with self._lock:
            self._local.setdefault(key, {})[email] = (user_id, now)

    def viewers(
        self, tenant: str, incident_key: str, *, exclude: Optional[str] = None
    ) -> List[Viewer]:
        """Current viewers, most recently seen first, minus ``exclude``."""
        key = self._key(tenant, incident_key)
        now = time.time()
        raw: Dict[str, Tuple[str, float]] = {}

        if self._redis is not None:
            try:
                for email, value in (self._redis.hgetall(key) or {}).items():
                    user_id, _, stamp = str(value).partition("|")
                    try:
                        raw[email] = (user_id, float(stamp))
                    except ValueError:
                        continue
            except Exception as exc:  # pragma: no cover - network
                logger.warning("presence read failed", extra={"error": str(exc)})
        else:
            with self._lock:
                raw = dict(self._local.get(key, {}))

        # Sorted on the raw timestamp, not on idle_seconds: that is truncated
        # to a whole second, and heartbeats inside the same second are the
        # normal case - rounding first makes the order arbitrary.
        fresh = [
            (stamp, email, user_id)
            for email, (user_id, stamp) in raw.items()
            if now - stamp <= self.ttl and email != exclude
        ]
        fresh.sort(reverse=True)
        return [
            Viewer(email=email, user_id=user_id, idle_seconds=int(now - stamp))
            for stamp, email, user_id in fresh
        ]

    def leave(self, tenant: str, incident_key: str, *, email: str) -> None:
        """Drop a viewer immediately, rather than waiting for the TTL."""
        key = self._key(tenant, incident_key)
        if self._redis is not None:
            try:
                self._redis.hdel(key, email)
                return
            except Exception as exc:  # pragma: no cover - network
                logger.warning("presence delete failed", extra={"error": str(exc)})
        with self._lock:
            self._local.get(key, {}).pop(email, None)

    def sweep(self, *, now: Optional[float] = None) -> int:
        """Drop expired in-process entries. Redis expires its own keys."""
        if self._redis is not None:
            return 0
        now = now if now is not None else time.time()
        dropped = 0
        with self._lock:
            for key in list(self._local):
                fresh = {
                    email: value
                    for email, value in self._local[key].items()
                    if now - value[1] <= self.ttl
                }
                dropped += len(self._local[key]) - len(fresh)
                if fresh:
                    self._local[key] = fresh
                else:
                    del self._local[key]
        return dropped
