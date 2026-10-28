"""Bounded Redis window: trimming, TTL, replacement, recovery from the system of record."""
from datetime import timedelta
from uuid import uuid4

from nextrace.contracts.v1 import LiveEventV1, TemporalStateV1
from nextrace.storage.cache import StateCache
from tests.conftest import NOW


def _state(sensor, i, n_flows=1):
    return TemporalStateV1(state_id=uuid4(), sensor_id=sensor, window_start=NOW + timedelta(seconds=10 * i), window_seconds=10,
                           schema_version=1, n_flows=n_flows, n_nodes=2, n_edges=1, total_bytes=10, total_pkts=2, features=[1.0] * 10)


def test_window_is_bounded_and_ordered(cache: StateCache):
    sensor = uuid4()
    for i in range(12):
        cache.push_state(_state(sensor, i))
    assert cache.state_count(sensor) == 5
    got = cache.recent_states(sensor)
    assert [s["window_start"] for s in got] == [_state(sensor, i).window_start.isoformat().replace("+00:00", "Z") for i in range(7, 12)]
    assert 0 < cache.ttl_remaining(sensor) <= 120


def test_rebuilt_window_replaces_same_slot(cache: StateCache):
    sensor = uuid4()
    cache.push_state(_state(sensor, 0, n_flows=1))
    cache.push_state(_state(sensor, 0, n_flows=99))
    got = cache.recent_states(sensor)
    assert len(got) == 1 and got[0]["n_flows"] == 99


def test_recovery_after_cache_loss(cache: StateCache):
    sensor = uuid4()
    durable = [_state(sensor, i) for i in range(8)]
    cache.push_states(durable)
    cache.r.flushall()                     # simulate restart without persistence
    assert cache.recent_states(sensor) == []
    assert cache.warm(sensor, durable) == 8
    assert cache.state_count(sensor) == 5  # still bounded after warm-up
    assert cache.recent_states(sensor)[-1]["state_id"] == str(durable[-1].state_id)


def test_current_forecast_and_live_events(cache: StateCache):
    sensor = uuid4()
    assert cache.get_current_forecast(sensor) is None
    cache.set_current_forecast(sensor, {"run_id": "r1", "p": 0.7})
    assert cache.get_current_forecast(sensor)["run_id"] == "r1"
    assert cache.r.ttl(f"nt:v1:forecast:{sensor}") > 0
    ps = cache.r.pubsub()
    ps.subscribe("nt:v1:live")
    ps.get_message(timeout=0.1)
    cache.publish(LiveEventV1(type="forecast", sensor_id=sensor, object_id="r1", at=NOW))
    msg = ps.get_message(timeout=0.5)
    assert msg and b'"type":"forecast"' in msg["data"]
