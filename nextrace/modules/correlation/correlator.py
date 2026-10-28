"""Alert correlation with delayed matching.

Pipeline position: after inference, before alerts. Steps:
  1. dedupe   predictions with the same (sensor, entity, technique set) inside `window_s` collapse into one event;
  2. group    events are keyed by entity (host when the prediction names hosts, else the sensor);
  3. match    the event's ordered technique sequence is scored against known attack patterns;
  4. delayed  events that did not match are re-scored once per grace period until `grace_s` elapses, because
              later evidence can complete a pattern (configurable window, as in ROSCA/alert-graph approaches).
State is in memory; a restart loses open (unmatched) groups, which is acceptable because alerts and runs are already
persisted. TODO(INTEGRATION): persist open groups in Redis with TTL if restarts prove frequent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from nextrace.contracts.findings import CorrelatedEventV1, EntityRefV1
from nextrace.contracts.v1 import PredictionV1
from nextrace.core.ids import uuid7


@dataclass(frozen=True)
class Pattern:
    """An ordered technique sequence representing a known multi-stage behaviour."""

    pattern_id: str
    techniques: tuple[str, ...]
    min_coverage: float = 0.6
    description: str = ""


def coverage(observed: list[str], pattern: tuple[str, ...]) -> float:
    """Fraction of the pattern matched as an ordered subsequence of the observed techniques."""
    i = 0
    for t in observed:
        if i < len(pattern) and t == pattern[i]:
            i += 1
    return i / len(pattern) if pattern else 0.0


@dataclass
class _Group:
    event_id: UUID
    sensor_id: UUID
    entity: EntityRefV1
    first_seen: datetime
    last_seen: datetime
    runs: list[UUID] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    keys: set[tuple] = field(default_factory=set)
    prediction_count: int = 0
    duplicate_count: int = 0
    max_probability: float = 0.0
    matched: str | None = None
    match_score: float | None = None
    last_match_check: datetime | None = None
    emitted: bool = False


class InMemoryCorrelator:
    def __init__(self, window_s: int, grace_s: int, patterns: list[Pattern] | None = None, max_groups: int = 50_000):
        self.window = timedelta(seconds=window_s)
        self.grace = timedelta(seconds=grace_s)
        self.patterns = list(patterns or [])
        self.max_groups = max_groups
        self._groups: dict[tuple, _Group] = {}

    # -- helpers --------------------------------------------------------------------------------
    @staticmethod
    def _entity(sensor_id: UUID, p: PredictionV1) -> EntityRefV1:
        hosts = getattr(p, "host_ids", None) or []
        if hosts:
            return EntityRefV1(kind="host", host_id=hosts[0], sensor_id=sensor_id)
        return EntityRefV1(kind="sensor", sensor_id=sensor_id)

    def _match(self, g: _Group, now: datetime) -> None:
        best, best_score = None, 0.0
        for pat in self.patterns:
            c = coverage(g.techniques, pat.techniques)
            if c >= pat.min_coverage and c > best_score:
                best, best_score = pat.pattern_id, c
        g.last_match_check = now
        if best is not None:
            g.matched, g.match_score = best, round(best_score, 4)

    def _event(self, g: _Group, late: bool) -> CorrelatedEventV1:
        return CorrelatedEventV1(event_id=g.event_id, sensor_id=g.sensor_id, entity=g.entity, first_seen=g.first_seen, last_seen=g.last_seen,
                                 source_run_ids=list(dict.fromkeys(g.runs)), prediction_count=g.prediction_count,
                                 duplicate_count=g.duplicate_count, technique_ids=list(dict.fromkeys(g.techniques)),
                                 max_probability=g.max_probability, matched_pattern_id=g.matched, pattern_match_score=g.match_score,
                                 late_matched=late)

    # -- port ------------------------------------------------------------------------------------
    def correlate(self, run_id: UUID, sensor_id: UUID, predictions: list[PredictionV1], now: datetime) -> list[CorrelatedEventV1]:
        touched: dict[UUID, _Group] = {}
        for p in predictions:
            if not p.is_malicious:
                continue
            ent = self._entity(sensor_id, p)
            gkey = (str(sensor_id), ent.kind, str(ent.host_id))
            g = self._groups.get(gkey)
            if g is not None and p.window_start - g.last_seen > self.window:
                g = None  # the previous group aged out; a new episode starts
            if g is None:
                if len(self._groups) >= self.max_groups:
                    oldest = min(self._groups, key=lambda k: self._groups[k].last_seen)
                    del self._groups[oldest]
                g = self._groups[gkey] = _Group(event_id=uuid7(), sensor_id=sensor_id, entity=ent, first_seen=p.window_start, last_seen=p.window_start)
            dkey = (tuple(sorted(p.technique_ids)), p.category)
            if dkey in g.keys and p.window_start - g.last_seen <= self.window:
                g.duplicate_count += 1
            else:
                g.keys.add(dkey)
                g.techniques.extend(p.technique_ids)
            g.prediction_count += 1
            g.runs.append(run_id)
            g.last_seen = max(g.last_seen, p.window_start)
            g.first_seen = min(g.first_seen, p.window_start)
            g.max_probability = max(g.max_probability, p.probability)
            touched[g.event_id] = g
        out = []
        for g in touched.values():
            self._match(g, now)
            g.emitted = True
            out.append(self._event(g, late=False))
        return out

    def late_match(self, now: datetime) -> list[CorrelatedEventV1]:
        """Re-score unmatched groups whose last activity is within the grace period but not re-checked since."""
        out = []
        expired = []
        for key, g in self._groups.items():
            age = now - g.last_seen
            if age > self.grace:
                expired.append(key)
                continue
            if g.matched is None and (g.last_match_check is None or g.last_match_check < g.last_seen):
                self._match(g, now)
                if g.matched is not None:
                    out.append(self._event(g, late=True))
        for key in expired:
            del self._groups[key]
        return out

    @property
    def open_groups(self) -> int:
        return len(self._groups)


# A small, clearly labelled seed of ordered patterns from ATT&CK tactics commonly reported in network data.
# These are illustrative sequences for tests and demos, not a validated pattern library (RESEARCH REQUIRED).
SEED_PATTERNS = [
    Pattern("recon-then-bruteforce", ("T1046", "T1110"), 1.0, "service discovery followed by brute force"),
    Pattern("recon-lateral", ("T1046", "T1021"), 1.0, "service discovery followed by remote services"),
    Pattern("exfil-chain", ("T1046", "T1021", "T1041"), 0.67, "discovery, lateral movement, exfiltration over C2"),
]
