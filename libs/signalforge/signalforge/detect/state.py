"""Sliding-window state used by stateful detections and by correlation.

Everything is time-based rather than count-based: entries older than the
window's timespan are pruned on every touch, so ``5 failures in 5 minutes``
means exactly that regardless of how fast events arrive.  Windows are keyed by
``(rule, tenant, group-by value)`` so one noisy principal cannot mask another.

The implementation is intentionally in-process: at the volumes SignalForge
targets, a detector shard owns a key range and keeps its own state, and the
event store remains the durable record.  Redis-backed windows would be the
next step for multi-replica detectors (see the roadmap).
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Hashable, List, Optional


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass
class WindowEntry:
    time: datetime
    ref: str  # event id or alert id
    value: Optional[Any] = None  # for value_count / cardinality
    label: Optional[str] = None  # rule id, used by temporal correlation
    payload: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.time.tzinfo is None:
            self.time = self.time.replace(tzinfo=timezone.utc)


class SlidingWindow:
    """Time-ordered entries within ``timespan`` seconds."""

    def __init__(self, timespan: int, max_entries: int = 10000) -> None:
        self.timespan = timespan
        self.max_entries = max_entries
        self._entries: Deque[WindowEntry] = deque()

    def add(self, entry: WindowEntry) -> None:
        # Late (out-of-order) arrivals are inserted in time order so ordered
        # correlation still sees the true sequence.
        if self._entries and entry.time < self._entries[-1].time:
            items = list(self._entries)
            items.append(entry)
            items.sort(key=lambda item: item.time)
            self._entries = deque(items)
        else:
            self._entries.append(entry)
        while len(self._entries) > self.max_entries:
            self._entries.popleft()

    def prune(self, now: Optional[datetime] = None) -> None:
        cutoff = (now or utcnow()) - timedelta(seconds=self.timespan)
        while self._entries and self._entries[0].time < cutoff:
            self._entries.popleft()

    def entries(self, now: Optional[datetime] = None) -> List[WindowEntry]:
        self.prune(now)
        return list(self._entries)

    def count(self, now: Optional[datetime] = None) -> int:
        self.prune(now)
        return len(self._entries)

    def distinct(self, now: Optional[datetime] = None) -> int:
        self.prune(now)
        return len({entry.value for entry in self._entries if entry.value is not None})

    def refs(self, now: Optional[datetime] = None) -> List[str]:
        return [entry.ref for entry in self.entries(now)]

    def labels(self, now: Optional[datetime] = None) -> List[str]:
        return [entry.label for entry in self.entries(now) if entry.label]

    @property
    def span(self) -> Optional[float]:
        if len(self._entries) < 2:
            return 0.0
        return (self._entries[-1].time - self._entries[0].time).total_seconds()

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


class WindowStore:
    """Thread-safe registry of sliding windows keyed by an arbitrary tuple."""

    def __init__(self, default_timespan: int = 300, max_keys: int = 100_000) -> None:
        self.default_timespan = default_timespan
        self.max_keys = max_keys
        self._windows: Dict[Hashable, SlidingWindow] = {}
        self._lock = threading.RLock()

    def window(self, key: Hashable, timespan: Optional[int] = None) -> SlidingWindow:
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = SlidingWindow(timespan or self.default_timespan)
                self._windows[key] = window
                if len(self._windows) > self.max_keys:
                    self._evict_locked()
            return window

    def _evict_locked(self) -> None:
        """Drop the emptiest windows first once the key budget is exceeded."""
        for key, _window in sorted(self._windows.items(), key=lambda item: len(item[1])):
            if len(self._windows) <= self.max_keys:
                break
            if key in self._windows:
                del self._windows[key]

    def sweep(self, now: Optional[datetime] = None) -> int:
        """Prune every window and forget the empty ones.  Returns keys dropped."""
        dropped = 0
        with self._lock:
            for key in list(self._windows):
                window = self._windows[key]
                window.prune(now)
                if not len(window):
                    del self._windows[key]
                    dropped += 1
        return dropped

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._windows)

    def clear(self) -> None:
        with self._lock:
            self._windows.clear()


class SuppressionCache:
    """Remembers "already fired" keys for a TTL, so alerts do not repeat."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._seen: Dict[Hashable, datetime] = {}
        self._lock = threading.RLock()

    def seen(
        self, key: Hashable, now: Optional[datetime] = None, ttl: Optional[int] = None
    ) -> bool:
        """True if ``key`` fired recently; otherwise records it and returns False."""
        reference = now or utcnow()
        horizon = timedelta(seconds=ttl if ttl is not None else self.ttl_seconds)
        with self._lock:
            previous = self._seen.get(key)
            if previous is not None and reference - previous < horizon:
                return True
            self._seen[key] = reference
            if len(self._seen) > 50_000:
                cutoff = reference - horizon
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
            return False

    def touch(self, key: Hashable, now: Optional[datetime] = None) -> None:
        with self._lock:
            self._seen[key] = now or utcnow()

    def forget(self, key: Hashable) -> None:
        with self._lock:
            self._seen.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
