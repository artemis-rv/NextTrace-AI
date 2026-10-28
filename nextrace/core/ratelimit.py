"""Token-bucket rate limiter keyed by principal (OWASP API4:2023 Unrestricted Resource Consumption)."""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, per_minute: int, burst: int | None = None, max_keys: int = 10_000):
        if per_minute < 1:
            raise ValueError("per_minute must be positive")
        self.rate = per_minute / 60.0
        self.burst = burst or per_minute
        self.max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        b = self._buckets.get(key)
        if b is None:
            if len(self._buckets) >= self.max_keys:
                self._evict(now)
            b = _Bucket(tokens=float(self.burst), updated=now)
            self._buckets[key] = b
        b.tokens = min(self.burst, b.tokens + (now - b.updated) * self.rate)
        b.updated = now
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False

    def _evict(self, now: float) -> None:
        stale = sorted(self._buckets.items(), key=lambda kv: kv[1].updated)[: max(1, self.max_keys // 10)]
        for k, _ in stale:
            del self._buckets[k]
