"""Event bus abstraction (Kafka/Redpanda in production, in-process for tests).

Both backends give the same guarantees the pipeline is designed around:

* **at-least-once delivery** - offsets are committed only after a batch has been
  processed, so a consumer crash replays the batch instead of losing it;
* **manual offset control** - a consumer that dies mid-batch resumes from its
  last commit, which combined with the event store's content-hash ``_id`` makes
  reprocessing idempotent;
* **a dead-letter topic** - records that cannot be normalized are parked rather
  than dropped or retried forever.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..config import Settings, get_settings

log = logging.getLogger("signalforge.storage.bus")


@dataclass
class Record:
    topic: str
    value: Dict[str, Any]
    key: Optional[str] = None
    offset: int = 0
    partition: int = 0
    timestamp: float = field(default_factory=time.time)
    headers: Dict[str, str] = field(default_factory=dict)


class Consumer:
    """A cursor over one or more topics for a single consumer group."""

    async def poll(self, max_records: int = 100, timeout: float = 0.5) -> List[Record]:
        raise NotImplementedError

    async def commit(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None

    @property
    def lag(self) -> int:
        return 0


class EventBus:
    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def publish(self, topic: str, value: Dict[str, Any],
                      key: Optional[str] = None) -> None:
        raise NotImplementedError

    async def publish_many(
        self,
        topic: str,
        values: Sequence[Dict[str, Any]],
        key_fn: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    ) -> int:
        for value in values:
            await self.publish(topic, value, key_fn(value) if key_fn else None)
        return len(values)

    def consumer(self, topics: Sequence[str], group: str) -> Consumer:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# In-process bus
# --------------------------------------------------------------------------- #
class InMemoryConsumer(Consumer):
    def __init__(self, bus: "InMemoryBus", topics: Sequence[str], group: str) -> None:
        self.bus = bus
        self.topics = list(topics)
        self.group = group
        self._inflight: Dict[str, int] = {}
        for topic in self.topics:
            bus.offsets.setdefault((group, topic), 0)

    async def poll(self, max_records: int = 100, timeout: float = 0.5) -> List[Record]:
        deadline = time.monotonic() + timeout
        while True:
            records: List[Record] = []
            for topic in self.topics:
                position = self.bus.offsets.get((self.group, topic), 0)
                partition = self.bus.log.get(topic, [])
                slice_ = partition[position:position + max_records - len(records)]
                if slice_:
                    records.extend(slice_)
                    self._inflight[topic] = position + len(slice_)
                if len(records) >= max_records:
                    break
            if records or time.monotonic() >= deadline:
                return records
            await asyncio.sleep(0.01)

    async def commit(self) -> None:
        for topic, position in self._inflight.items():
            self.bus.offsets[(self.group, topic)] = position
        self._inflight.clear()

    async def close(self) -> None:
        # Uncommitted records stay uncommitted: the next consumer replays them.
        self._inflight.clear()

    @property
    def lag(self) -> int:
        return sum(
            max(0, len(self.bus.log.get(topic, [])) - self.bus.offsets.get((self.group, topic), 0))
            for topic in self.topics
        )


class InMemoryBus(EventBus):
    """Append-only log with per-group offsets - Kafka semantics, no broker."""

    def __init__(self) -> None:
        self.log: Dict[str, List[Record]] = {}
        self.offsets: Dict[Any, int] = {}
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, value: Dict[str, Any],
                      key: Optional[str] = None) -> None:
        async with self._lock:
            partition = self.log.setdefault(topic, [])
            partition.append(
                Record(topic=topic, value=value, key=key, offset=len(partition))
            )

    def consumer(self, topics: Sequence[str], group: str) -> Consumer:
        return InMemoryConsumer(self, topics, group)

    # -- test/introspection helpers ---------------------------------------
    def messages(self, topic: str) -> List[Dict[str, Any]]:
        return [record.value for record in self.log.get(topic, [])]

    def depth(self, topic: str) -> int:
        return len(self.log.get(topic, []))

    def clear(self) -> None:
        self.log.clear()
        self.offsets.clear()


# --------------------------------------------------------------------------- #
# Kafka / Redpanda bus
# --------------------------------------------------------------------------- #
class KafkaConsumerWrapper(Consumer):
    def __init__(self, consumer: Any) -> None:
        self._consumer = consumer
        self._has_uncommitted = False

    async def poll(self, max_records: int = 100, timeout: float = 0.5) -> List[Record]:
        batches = await self._consumer.getmany(
            timeout_ms=int(timeout * 1000), max_records=max_records
        )
        records: List[Record] = []
        for topic_partition, messages in batches.items():
            for message in messages:
                records.append(Record(
                    topic=topic_partition.topic,
                    partition=topic_partition.partition,
                    value=json.loads(message.value.decode("utf-8")),
                    key=message.key.decode("utf-8") if message.key else None,
                    offset=message.offset,
                    timestamp=(message.timestamp or 0) / 1000.0,
                ))
        self._has_uncommitted = bool(records)
        return records

    async def commit(self) -> None:
        if self._has_uncommitted:
            await self._consumer.commit()
            self._has_uncommitted = False

    async def close(self) -> None:
        await self._consumer.stop()


class KafkaBus(EventBus):
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._producer: Any = None

    async def start(self) -> None:
        if self._producer is not None:
            return
        from aiokafka import AIOKafkaProducer

        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            client_id=self.settings.kafka_client_id,
            value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
            key_serializer=lambda key: key.encode("utf-8") if key else None,
            acks="all",
            enable_idempotence=True,
            linger_ms=20,
            compression_type="gzip",
        )
        await self._producer.start()

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None

    async def publish(self, topic: str, value: Dict[str, Any],
                      key: Optional[str] = None) -> None:
        await self.start()
        await self._producer.send_and_wait(topic, value=value, key=key)

    def consumer(self, topics: Sequence[str], group: str) -> Consumer:
        from aiokafka import AIOKafkaConsumer

        consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            group_id=group,
            # Manual commits: a crash mid-batch replays rather than skips.
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            max_poll_records=self.settings.max_poll_records,
        )
        return _LazyKafkaConsumer(consumer)


class _LazyKafkaConsumer(Consumer):
    """Starts the aiokafka consumer on first poll so ``consumer()`` stays sync."""

    def __init__(self, consumer: Any) -> None:
        self._raw = consumer
        self._wrapper: Optional[KafkaConsumerWrapper] = None

    async def _ensure(self) -> KafkaConsumerWrapper:
        if self._wrapper is None:
            await self._raw.start()
            self._wrapper = KafkaConsumerWrapper(self._raw)
        return self._wrapper

    async def poll(self, max_records: int = 100, timeout: float = 0.5) -> List[Record]:
        wrapper = await self._ensure()
        return await wrapper.poll(max_records, timeout)

    async def commit(self) -> None:
        if self._wrapper is not None:
            await self._wrapper.commit()

    async def close(self) -> None:
        if self._wrapper is not None:
            await self._wrapper.close()
            self._wrapper = None


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
_BUS: Optional[EventBus] = None


def get_bus(settings: Optional[Settings] = None, *, refresh: bool = False) -> EventBus:
    global _BUS
    if _BUS is not None and not refresh:
        return _BUS
    settings = settings or get_settings()
    _BUS = KafkaBus(settings) if settings.use_kafka else InMemoryBus()
    return _BUS


def reset_bus() -> None:
    global _BUS
    _BUS = None
