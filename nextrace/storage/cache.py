"""Bounded Redis cache of recent temporal states plus the live update channel.

Redis is a cache, not the system of record: every key has a TTL, every per-sensor window is
trimmed to `max_states` entries, and `warm()` rebuilds a window from PostgreSQL after a flush or
restart. Recommended server settings: maxmemory set, maxmemory-policy allkeys-lru.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import UUID

import redis

from nextrace.contracts.v1 import LiveEventV1, TemporalStateV1

NS = "nt:v1"
LIVE_CHANNEL = f"{NS}:live"


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, separators=(",", ":"), sort_keys=True)


class StateCache:
    def __init__(self, client: redis.Redis, max_states: int, ttl_seconds: int):
        if max_states < 1 or ttl_seconds < 1:
            raise ValueError("max_states and ttl_seconds must be positive")
        self.r = client
        self.max_states = max_states
        self.ttl = ttl_seconds

    @staticmethod
    def _states_key(sensor_id: UUID | str) -> str:
        return f"{NS}:states:{sensor_id}"

    @staticmethod
    def _forecast_key(sensor_id: UUID | str) -> str:
        return f"{NS}:forecast:{sensor_id}"

    # -- temporal states -----------------------------------------------------------------------
    def push_state(self, state: TemporalStateV1) -> None:
        key = self._states_key(state.sensor_id)
        score = state.window_start.timestamp()
        pipe = self.r.pipeline(transaction=True)
        pipe.zremrangebyscore(key, score, score)          # rebuilds replace the same window
        pipe.zadd(key, {_dumps(state.model_dump(mode="json")): score})
        pipe.zremrangebyrank(key, 0, -(self.max_states + 1))  # keep the newest max_states
        pipe.expire(key, self.ttl)
        pipe.execute()

    def push_states(self, states: Iterable[TemporalStateV1]) -> int:
        n = 0
        for s in states:
            self.push_state(s)
            n += 1
        return n

    def recent_states(self, sensor_id: UUID | str, n: int | None = None) -> list[dict[str, Any]]:
        n = self.max_states if n is None else min(n, self.max_states)
        raw = self.r.zrevrange(self._states_key(sensor_id), 0, n - 1)
        return [json.loads(x) for x in reversed(raw)]  # oldest first

    def state_count(self, sensor_id: UUID | str) -> int:
        return int(self.r.zcard(self._states_key(sensor_id)))

    def ttl_remaining(self, sensor_id: UUID | str) -> int:
        return int(self.r.ttl(self._states_key(sensor_id)))

    def warm(self, sensor_id: UUID | str, states: Iterable[TemporalStateV1]) -> int:
        """Rebuild the window from durable rows (oldest first) after a miss."""
        self.r.delete(self._states_key(sensor_id))
        return self.push_states(states)

    # -- current forecast ----------------------------------------------------------------------
    def set_current_forecast(self, sensor_id: UUID | str, payload: dict[str, Any]) -> None:
        self.r.set(self._forecast_key(sensor_id), _dumps(payload), ex=self.ttl)

    def get_current_forecast(self, sensor_id: UUID | str) -> dict[str, Any] | None:
        raw = self.r.get(self._forecast_key(sensor_id))
        return None if raw is None else json.loads(raw)

    # -- live channel --------------------------------------------------------------------------
    def publish(self, event: LiveEventV1) -> int:
        return int(self.r.publish(LIVE_CHANNEL, _dumps(event.model_dump(mode="json"))))

    def publish_state(self, state: TemporalStateV1) -> int:
        return self.publish(LiveEventV1(type="state", sensor_id=state.sensor_id, object_id=str(state.state_id),
                                        at=datetime.now(timezone.utc),
                                        payload={"window_start": state.window_start.isoformat(), "n_flows": state.n_flows}))
