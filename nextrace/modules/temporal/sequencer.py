"""Streaming temporal-state construction with event time, watermarks and allowed lateness.

Semantics (borrowed from stream processing, see Flink "allowed lateness"):
  * a flow belongs to the window containing its ts_start (same rule as the SQL builder in services.states);
  * the per-sensor watermark is max(ts_start seen) - allowed_lateness;
  * a window closes when the watermark passes its end; closed windows are emitted as TemporalStateV1;
  * a flow arriving for an already-closed window is *late*: with late_policy='refire' the window is
    recomputed and re-emitted (the DB upsert and cache replace the same window), with 'drop' it is counted.
Feature definitions are WINDOW_FEATURES_V1 (shared with the SQL builder); a conformance test keeps both equal.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Literal
from uuid import UUID

from nextrace.contracts.errors import ContractViolation
from nextrace.contracts.temporal import StateSequenceV1
from nextrace.contracts.v1 import FlowRecordV1, TemporalStateV1
from nextrace.core.ids import uuid7
from nextrace.services.states import WINDOW_FEATURES_V1

FAILED_STATES = frozenset({"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"})
EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)
SCHEMA_VERSION = 1


def window_start_for(ts: datetime, window_seconds: int) -> datetime:
    """Same binning as SQL date_bin(interval, ts, '2000-01-01')."""
    delta = (ts - EPOCH).total_seconds()
    return EPOCH + timedelta(seconds=(delta // window_seconds) * window_seconds)


@dataclass
class _Window:
    start: datetime
    n_flows: int = 0
    hosts: set[str] = field(default_factory=set)
    edges: set[tuple[str, str]] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    total_bytes: int = 0
    total_pkts: int = 0
    tcp: int = 0
    udp: int = 0
    failed: int = 0
    duration_sum: float = 0.0
    duration_n: int = 0
    emitted: bool = False
    state_id: UUID | None = None
    late_updates: int = 0

    def add(self, f: FlowRecordV1) -> None:
        self.n_flows += 1
        s, d = str(f.src_ip), str(f.dst_ip)
        self.hosts.add(s)
        self.hosts.add(d)
        self.edges.add((s, d))
        if f.dst_port is not None:
            self.dst_ports.add(f.dst_port)
        self.total_bytes += f.orig_bytes + f.resp_bytes
        self.total_pkts += f.orig_pkts + f.resp_pkts
        if f.proto == 6:
            self.tcp += 1
        elif f.proto == 17:
            self.udp += 1
        if f.conn_state in FAILED_STATES:
            self.failed += 1
        if f.duration_ms is not None:
            self.duration_sum += f.duration_ms
            self.duration_n += 1

    def features(self) -> list[float]:
        n = self.n_flows
        return [
            float(n), float(len(self.hosts)), float(len(self.edges)), float(self.total_bytes), float(self.total_pkts),
            float(len(self.dst_ports)),
            self.tcp / n if n else 0.0, self.udp / n if n else 0.0, self.failed / n if n else 0.0,
            self.duration_sum / self.duration_n if self.duration_n else 0.0,
        ]

    def to_state(self, sensor_id: UUID, window_seconds: int) -> TemporalStateV1:
        if self.state_id is None:
            self.state_id = uuid7()
        summary = {"late_updates": self.late_updates} if self.late_updates else {}
        return TemporalStateV1(
            state_id=self.state_id, sensor_id=sensor_id, window_start=self.start, window_seconds=window_seconds,
            schema_version=SCHEMA_VERSION, n_flows=self.n_flows, n_nodes=len(self.hosts), n_edges=len(self.edges),
            total_bytes=self.total_bytes, total_pkts=self.total_pkts, summary=summary, features=self.features())


@dataclass
class SequencerStats:
    flows_in: int = 0
    states_emitted: int = 0
    late_flows: int = 0
    late_dropped: int = 0
    late_refired: int = 0
    out_of_order_flows: int = 0


class StreamingSequencer:
    """Implements contracts.ports.TemporalSequencer. One instance serves many sensors."""

    def __init__(self, window_seconds: int, allowed_lateness_s: int, feature_schema_id: UUID,
                 late_policy: Literal["drop", "refire"] = "refire", max_open_windows: int = 10_000,
                 history: int = 4096):
        if window_seconds < 1 or allowed_lateness_s < 0:
            raise ValueError("window_seconds must be positive and lateness non-negative")
        self.window_seconds = window_seconds
        self.lateness = timedelta(seconds=allowed_lateness_s)
        self.feature_schema_id = feature_schema_id
        self.late_policy = late_policy
        self.max_open_windows = max_open_windows
        self.history = history
        self._open: dict[UUID, dict[datetime, _Window]] = defaultdict(dict)
        self._closed: dict[UUID, list[TemporalStateV1]] = defaultdict(list)
        self._max_ts: dict[UUID, datetime] = {}
        self._last_ts: dict[UUID, datetime] = {}
        self.stats = SequencerStats()
        self.feature_names = [f["name"] for f in WINDOW_FEATURES_V1]

    # -- ingestion ------------------------------------------------------------------------------
    def watermark(self, sensor_id: UUID) -> datetime | None:
        m = self._max_ts.get(sensor_id)
        return None if m is None else m - self.lateness

    def ingest(self, flows: Iterable[FlowRecordV1], sensor_id: UUID) -> list[TemporalStateV1]:
        emitted: list[TemporalStateV1] = []
        windows = self._open[sensor_id]
        for f in flows:
            self.stats.flows_in += 1
            ws = window_start_for(f.ts_start, self.window_seconds)
            last = self._last_ts.get(sensor_id)
            if last is not None and f.ts_start < last:
                self.stats.out_of_order_flows += 1
            self._last_ts[sensor_id] = f.ts_start
            wm = self.watermark(sensor_id)
            if wm is not None and ws + timedelta(seconds=self.window_seconds) <= wm:
                self.stats.late_flows += 1
                if self.late_policy == "drop" or ws not in windows:
                    self.stats.late_dropped += 1
                    continue
                w = windows[ws]
                w.add(f)
                w.late_updates += 1
                self.stats.late_refired += 1
                emitted.append(self._replace_closed(sensor_id, w))
                continue
            w = windows.get(ws)
            if w is None:
                if len(windows) >= self.max_open_windows:
                    raise ContractViolation("too many open windows; input is not time-ordered enough", sensor_id=str(sensor_id))
                w = windows[ws] = _Window(start=ws)
            w.add(f)
            if sensor_id not in self._max_ts or f.ts_start > self._max_ts[sensor_id]:
                self._max_ts[sensor_id] = f.ts_start
        emitted.extend(self._close_ready(sensor_id))
        return emitted

    def _close_ready(self, sensor_id: UUID) -> list[TemporalStateV1]:
        wm = self.watermark(sensor_id)
        if wm is None:
            return []
        out: list[TemporalStateV1] = []
        windows = self._open[sensor_id]
        for ws in sorted(windows):
            w = windows[ws]
            if w.emitted or ws + timedelta(seconds=self.window_seconds) > wm:
                continue
            w.emitted = True
            st = w.to_state(sensor_id, self.window_seconds)
            out.append(st)
            self._closed[sensor_id].append(st)
            self.stats.states_emitted += 1
        self._gc(sensor_id)
        return out

    def _replace_closed(self, sensor_id: UUID, w: _Window) -> TemporalStateV1:
        st = w.to_state(sensor_id, self.window_seconds)
        closed = self._closed[sensor_id]
        for i, old in enumerate(closed):
            if old.window_start == st.window_start:
                closed[i] = st
                break
        return st

    def _gc(self, sensor_id: UUID) -> None:
        """Keep emitted windows only while late data can still arrive, keep bounded history."""
        wm = self.watermark(sensor_id)
        windows = self._open[sensor_id]
        if wm is not None:
            horizon = wm - self.lateness - timedelta(seconds=self.window_seconds)
            for ws in [k for k, w in windows.items() if w.emitted and k < horizon]:
                del windows[ws]
        closed = self._closed[sensor_id]
        if len(closed) > self.history:
            del closed[: len(closed) - self.history]

    def flush(self, sensor_id: UUID) -> list[TemporalStateV1]:
        """Close every open window (end of replay / shutdown). Live use should prefer time-based closing."""
        windows = self._open[sensor_id]
        out: list[TemporalStateV1] = []
        for ws in sorted(windows):
            w = windows[ws]
            if not w.emitted:
                w.emitted = True
                st = w.to_state(sensor_id, self.window_seconds)
                out.append(st)
                self._closed[sensor_id].append(st)
                self.stats.states_emitted += 1
        windows.clear()
        return out

    # -- sequences -------------------------------------------------------------------------------
    def closed_states(self, sensor_id: UUID) -> list[TemporalStateV1]:
        return list(self._closed.get(sensor_id, []))

    def sequence(self, sensor_id: UUID, length: int, up_to: datetime | None = None) -> StateSequenceV1 | None:
        """The last `length` closed states ending at `up_to` (inclusive), or the newest when `up_to` is None."""
        states = self._closed.get(sensor_id, [])
        if up_to is not None:
            states = [s for s in states if s.window_start <= up_to]
        if not states:
            return None
        return build_sequence(sensor_id, states[-length:], self.window_seconds, self.feature_schema_id)

    def late_flows_dropped(self) -> int:
        return self.stats.late_dropped


def build_sequence(sensor_id: UUID, states: list[TemporalStateV1], window_seconds: int, feature_schema_id: UUID) -> StateSequenceV1:
    """Ordered sequence with explicit gaps. Gaps are not filled with zeros here: the model owner decides
    (masking vs. imputation) and records that decision in the model version."""
    states = sorted(states, key=lambda s: s.window_start)
    missing: list[datetime] = []
    step = timedelta(seconds=window_seconds)
    for a, b in zip(states, states[1:]):
        cur = a.window_start + step
        while cur < b.window_start:
            missing.append(cur)
            cur += step
    return StateSequenceV1(sensor_id=sensor_id, feature_schema_id=feature_schema_id, window_seconds=window_seconds,
                           states=states, missing_windows=missing, complete=not missing)
