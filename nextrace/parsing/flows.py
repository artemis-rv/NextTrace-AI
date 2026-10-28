"""Bidirectional flow assembly from packet observations.

Flow identity is the canonical 5-tuple; the originator is the first packet's source (CICFlowMeter and Zeek
convention). Expiry follows IPFIX practice (RFC 7011: inactivity, active timeout, or end-of-connection);
the default timeouts mirror Cisco Flexible NetFlow defaults (inactive 15 s, active 1800 s) and are
configuration, not truth. `conn_state` is an approximation of Zeek's vocabulary from TCP flags.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from nextrace.contracts.observations import PacketObservationV1
from nextrace.contracts.v1 import FlowRecordV1

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10
FlowKey = tuple[str, int, str, int, int]


@dataclass
class _Flow:
    key: FlowKey
    orig_ip: str
    orig_port: int
    resp_ip: str
    resp_port: int
    proto: int
    ts_first: datetime
    ts_last: datetime
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_flags: int = 0
    resp_flags: int = 0
    history: list[str] = field(default_factory=list)
    segment_id: UUID | None = None

    def add(self, p: PacketObservationV1, from_orig: bool) -> None:
        self.ts_last = max(self.ts_last, p.ts)
        if from_orig:
            self.orig_pkts += 1
            self.orig_bytes += p.payload_len
            self.orig_flags |= (p.tcp_flags or 0)
        else:
            self.resp_pkts += 1
            self.resp_bytes += p.payload_len
            self.resp_flags |= (p.tcp_flags or 0)
        if p.tcp_flags is not None and len(self.history) < 64:
            ch = _hist_char(p.tcp_flags)
            if ch:
                self.history.append(ch if from_orig else ch.lower())

    def conn_state(self) -> str | None:
        if self.proto != 6:
            return "SF" if self.resp_pkts else "S0"
        o, r = self.orig_flags, self.resp_flags
        if o & SYN and not r:
            return "S0"
        if o & SYN and r & RST and not (r & SYN):
            return "REJ"
        if o & FIN and r & FIN:
            return "SF"
        if r & RST and o & SYN:
            return "RSTR"
        if o & RST and r & SYN:
            return "RSTO"
        if o & SYN and r & SYN and not (o & FIN or r & FIN):
            return "S1"
        if o & FIN and not (r & FIN):
            return "S2"
        if r & FIN and not (o & FIN):
            return "S3"
        return "OTH"

    def to_record(self) -> FlowRecordV1:
        dur = int((self.ts_last - self.ts_first).total_seconds() * 1000)
        return FlowRecordV1(
            ts_start=self.ts_first, ts_end=self.ts_last, src_ip=self.orig_ip, src_port=self.orig_port,
            dst_ip=self.resp_ip, dst_port=self.resp_port, proto=self.proto, duration_ms=dur,
            orig_bytes=self.orig_bytes, resp_bytes=self.resp_bytes, orig_pkts=self.orig_pkts, resp_pkts=self.resp_pkts,
            conn_state=self.conn_state(), history="".join(self.history) or None, pcap_segment_id=self.segment_id)


def _hist_char(flags: int) -> str:
    if flags & SYN and flags & ACK:
        return "H"
    if flags & SYN:
        return "S"
    if flags & FIN:
        return "F"
    if flags & RST:
        return "R"
    if flags & ACK:
        return "A"
    return ""


def canonical_key(p: PacketObservationV1) -> FlowKey:
    a = (str(p.src_ip), p.src_port or 0)
    b = (str(p.dst_ip), p.dst_port or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], p.proto or 0)


@dataclass
class AssemblerStats:
    packets: int = 0
    skipped_non_ip: int = 0
    skipped_malformed: int = 0
    flows_emitted: int = 0
    expired_inactive: int = 0
    expired_active: int = 0
    closed_by_flags: int = 0
    evicted_table_full: int = 0


class FlowAssembler:
    def __init__(self, inactive_timeout_s: int = 15, active_timeout_s: int = 1800, max_flows: int = 500_000):
        self.inactive = timedelta(seconds=inactive_timeout_s)
        self.active = timedelta(seconds=active_timeout_s)
        self.max_flows = max_flows
        self._flows: dict[FlowKey, _Flow] = {}
        self.stats = AssemblerStats()

    @property
    def open_flows(self) -> int:
        return len(self._flows)

    def feed(self, p: PacketObservationV1) -> list[FlowRecordV1]:
        """Add one packet; returns flows that completed (by flags or timeouts evaluated at this packet's time)."""
        self.stats.packets += 1
        if p.malformed:
            self.stats.skipped_malformed += 1
            return self.expire(p.ts)
        if p.src_ip is None or p.proto is None:
            self.stats.skipped_non_ip += 1
            return self.expire(p.ts)
        out = self.expire(p.ts)
        key = canonical_key(p)
        f = self._flows.get(key)
        if f is None:
            if len(self._flows) >= self.max_flows:
                oldest = min(self._flows.values(), key=lambda x: x.ts_last)
                del self._flows[oldest.key]
                out.append(oldest.to_record())
                self.stats.evicted_table_full += 1
                self.stats.flows_emitted += 1
            f = _Flow(key=key, orig_ip=str(p.src_ip), orig_port=p.src_port or 0, resp_ip=str(p.dst_ip), resp_port=p.dst_port or 0,
                      proto=p.proto, ts_first=p.ts, ts_last=p.ts, segment_id=p.pcap_segment_id)
            self._flows[key] = f
        from_orig = str(p.src_ip) == f.orig_ip and (p.src_port or 0) == f.orig_port
        f.add(p, from_orig)
        if p.proto == 6 and p.tcp_flags is not None and (p.tcp_flags & RST or (f.orig_flags & FIN and f.resp_flags & FIN)):
            del self._flows[key]
            self.stats.closed_by_flags += 1
            self.stats.flows_emitted += 1
            out.append(f.to_record())
        return out

    def expire(self, now: datetime) -> list[FlowRecordV1]:
        out: list[FlowRecordV1] = []
        for key in [k for k, f in self._flows.items() if now - f.ts_last > self.inactive or now - f.ts_first > self.active]:
            f = self._flows.pop(key)
            if now - f.ts_last > self.inactive:
                self.stats.expired_inactive += 1
            else:
                self.stats.expired_active += 1
            self.stats.flows_emitted += 1
            out.append(f.to_record())
        return out

    def flush(self) -> list[FlowRecordV1]:
        out = [f.to_record() for f in self._flows.values()]
        self.stats.flows_emitted += len(out)
        self._flows.clear()
        return out
