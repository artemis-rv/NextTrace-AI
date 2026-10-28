"""Bounded in-process queues with explicit backpressure (no broker until a benchmark demands one).

Three policies, chosen per queue from configuration:
  block        producer awaits free capacity (default; preserves every item, slows capture)
  shed_oldest  drop the oldest queued item and count it (keeps latency bounded, loses data visibly)
  reject       raise contracts.errors.Backpressure to the producer (API ingestion)
Every drop is counted and reported through health; nothing is silently lost.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generic, Literal, TypeVar

from nextrace.contracts.errors import Backpressure
from nextrace.contracts.ops import ComponentHealthV1

T = TypeVar("T")
Policy = Literal["block", "shed_oldest", "reject"]


@dataclass
class QueueStats:
    enqueued: int = 0
    dequeued: int = 0
    shed: int = 0
    rejected: int = 0
    blocked_waits: int = 0
    max_depth: int = 0
    last_enqueue_at: datetime | None = None
    last_dequeue_at: datetime | None = None
    extra: dict[str, float] = field(default_factory=dict)


class BoundedQueue(Generic[T]):
    def __init__(self, name: str, capacity: int, policy: Policy = "block"):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.name = name
        self.capacity = capacity
        self.policy = policy
        self._q: asyncio.Queue[T] = asyncio.Queue(maxsize=capacity)
        self.stats = QueueStats()
        self._closed = False

    @property
    def depth(self) -> int:
        return self._q.qsize()

    @property
    def closed(self) -> bool:
        return self._closed

    async def put(self, item: T) -> bool:
        """Returns True if the item was queued, False if it was shed. Raises Backpressure under 'reject'."""
        if self._closed:
            raise RuntimeError(f"queue {self.name} is closed")
        if self._q.full():
            if self.policy == "reject":
                self.stats.rejected += 1
                raise Backpressure(f"queue {self.name} full", queue=self.name, depth=self.depth)
            if self.policy == "shed_oldest":
                try:
                    self._q.get_nowait()
                    self._q.task_done()
                    self.stats.shed += 1
                except asyncio.QueueEmpty:  # pragma: no cover - race with a consumer
                    pass
            else:
                self.stats.blocked_waits += 1
        await self._q.put(item)
        self.stats.enqueued += 1
        self.stats.max_depth = max(self.stats.max_depth, self.depth)
        self.stats.last_enqueue_at = datetime.now(timezone.utc)
        return True

    def put_nowait(self, item: T) -> bool:
        """Synchronous variant for non-async producers (e.g. a capture thread)."""
        if self._closed:
            raise RuntimeError(f"queue {self.name} is closed")
        if self._q.full():
            if self.policy == "reject":
                self.stats.rejected += 1
                raise Backpressure(f"queue {self.name} full", queue=self.name, depth=self.depth)
            if self.policy == "shed_oldest":
                self._q.get_nowait()
                self._q.task_done()
                self.stats.shed += 1
            else:
                self.stats.rejected += 1
                raise Backpressure(f"queue {self.name} full and producer cannot block", queue=self.name)
        self._q.put_nowait(item)
        self.stats.enqueued += 1
        self.stats.max_depth = max(self.stats.max_depth, self.depth)
        self.stats.last_enqueue_at = datetime.now(timezone.utc)
        return True

    async def get(self, timeout_s: float | None = None) -> T | None:
        """None on timeout or when closed and drained."""
        if self._closed and self._q.empty():
            return None
        try:
            item = await asyncio.wait_for(self._q.get(), timeout=timeout_s) if timeout_s else await self._q.get()
        except asyncio.TimeoutError:
            return None
        self._q.task_done()
        self.stats.dequeued += 1
        self.stats.last_dequeue_at = datetime.now(timezone.utc)
        return item

    def close(self) -> None:
        self._closed = True

    def health(self) -> ComponentHealthV1:
        s = self.stats
        util = self.depth / self.capacity
        status = "ok" if util < 0.8 and s.shed == 0 and s.rejected == 0 else "degraded"
        return ComponentHealthV1(
            name=f"queue.{self.name}", status=status, checked_at=datetime.now(timezone.utc),
            detail=f"policy={self.policy}",
            metrics={"depth": float(self.depth), "capacity": float(self.capacity), "utilisation": round(util, 3),
                     "enqueued": float(s.enqueued), "dequeued": float(s.dequeued), "shed": float(s.shed),
                     "rejected": float(s.rejected), "blocked_waits": float(s.blocked_waits), "max_depth": float(s.max_depth)})
