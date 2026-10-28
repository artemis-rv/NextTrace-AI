"""Person 4 module: header decoding, flow assembly, replay source, malformed input, backpressure."""
from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest

from nextrace.contracts.errors import Backpressure
from nextrace.core.bus import BoundedQueue
from nextrace.modules.capture.sources import PcapReplaySource
from nextrace.parsing.decode import decode
from nextrace.parsing.flows import FlowAssembler
from tests.backend_helpers import ACK, FIN, RST, SYN, an_hour_ago, handshake, scenario_packets, tcp_packet, udp_packet, write_pcap

SID = uuid.uuid4()


def test_decode_tcp_udp_and_payload_is_not_copied():
    t = an_hour_ago().timestamp()
    o = decode(t, tcp_packet("10.0.0.1", 1234, "10.0.1.1", 80, SYN | ACK, b"secret-payload"), 100, 1, SID)
    assert (str(o.src_ip), o.src_port, str(o.dst_ip), o.dst_port, o.proto, o.tcp_flags) == ("10.0.0.1", 1234, "10.0.1.1", 80, 6, SYN | ACK)
    assert o.payload_len == len(b"secret-payload") and "secret" not in o.model_dump_json()
    u = decode(t, udp_packet("10.0.0.2", 5353, "10.0.1.53", 53, b"q" * 20), 80, 1, SID)
    assert u.proto == 17 and u.payload_len == 20 and not u.malformed


def test_decode_malformed_and_truncated_do_not_raise():
    t = an_hour_ago().timestamp()
    bad = decode(t, b"\x00" * 30, 30, 1, SID)             # ethertype 0 -> non-IP, counted, not malformed
    assert not bad.malformed and bad.src_ip is None
    short_ip = decode(t, tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, SYN)[:20], 60, 1, SID)
    assert short_ip.malformed
    trunc = decode(t, tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, SYN)[:40], 1500, 1, SID)
    assert trunc.truncated and trunc.wirelen == 1500
    vlan = tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, SYN)
    vlan = vlan[:12] + b"\x81\x00\x00\x05" + vlan[12:]
    assert str(decode(t, vlan, len(vlan), 1, SID).dst_ip) == "10.0.0.2"
    unknown_link = decode(t, b"\x01\x02", 2, 999, SID)
    assert unknown_link.src_ip is None and not unknown_link.malformed


def test_assembler_bidirectional_flow_and_states():
    base = an_hour_ago()
    asm = FlowAssembler(inactive_timeout_s=15)
    out = []
    for ts, data in handshake(base.timestamp(), "10.0.0.1", 40000, "10.0.1.10", 80):
        out += asm.feed(decode(ts, data, len(data), 1, SID))
    assert len(out) == 1
    f = out[0]
    assert (str(f.src_ip), f.src_port, str(f.dst_ip), f.dst_port) == ("10.0.0.1", 40000, "10.0.1.10", 80)
    assert f.conn_state == "SF" and f.orig_pkts == 4 and f.resp_pkts == 3 and f.resp_bytes > f.orig_bytes
    assert f.history and f.history[0] == "S" and "h" in f.history
    # SYN with no answer -> S0 after the inactivity timeout
    out = asm.feed(decode(base.timestamp() + 100, tcp_packet("10.0.0.9", 1, "10.0.1.20", 22, SYN), 60, 1, SID))
    assert out == []
    out = asm.feed(decode(base.timestamp() + 130, tcp_packet("10.0.0.9", 2, "10.0.1.20", 23, SYN), 60, 1, SID))
    assert len(out) == 1 and out[0].conn_state == "S0" and asm.stats.expired_inactive == 1
    # RST from responder -> REJ, closed immediately
    asm.feed(decode(base.timestamp() + 200, tcp_packet("10.0.0.9", 3, "10.0.1.20", 25, SYN), 60, 1, SID))
    out = asm.feed(decode(base.timestamp() + 200.01, tcp_packet("10.0.1.20", 25, "10.0.0.9", 3, RST | ACK), 60, 1, SID))
    assert len(out) == 1 and out[0].conn_state == "REJ"
    assert asm.flush() == [] and asm.open_flows == 0  # the port-23 SYN had already expired (inactivity) before the REJ exchange


def test_assembler_table_full_evicts_oldest_visibly():
    base = an_hour_ago().timestamp()
    asm = FlowAssembler(max_flows=3)
    for i in range(5):
        asm.feed(decode(base + i, tcp_packet("10.0.0.1", 1000 + i, "10.0.1.1", 80, SYN), 60, 1, SID))
    assert asm.open_flows == 3 and asm.stats.evicted_table_full == 2


def test_replay_source_emits_ordered_batches_and_honest_health(tmp_path):
    path = write_pcap(tmp_path / "s.pcap", scenario_packets(an_hour_ago()))
    src = PcapReplaySource(path, SID, batch_flows=50)

    async def collect():
        return [b async for b in src.batches()]

    batches = asyncio.run(collect())
    assert batches and [b.batch_seq for b in batches] == list(range(len(batches)))
    flows = [f for b in batches for f in b.flows]
    assert len(flows) >= 60 + 120 + 12
    for b in batches:
        assert all(x.ts_start <= y.ts_start for x, y in zip(b.flows, b.flows[1:]))
    h = src.health()
    assert h.packets_seen > 0 and h.drop_counters_available is False and h.kernel_drops is None
    assert h.flows_emitted == len(flows) and h.source_kind == "pcap_replay"


def test_bounded_queue_policies():
    async def run():
        q = BoundedQueue("t", 2, "reject")
        await q.put(1); await q.put(2)
        with pytest.raises(Backpressure):
            await q.put(3)
        assert q.stats.rejected == 1 and q.health().status == "degraded"
        s = BoundedQueue("s", 2, "shed_oldest")
        await s.put(1); await s.put(2); await s.put(3)
        assert s.stats.shed == 1 and await s.get() == 2
        b = BoundedQueue("b", 1, "block")
        await b.put(1)
        putter = asyncio.create_task(b.put(2))
        await asyncio.sleep(0.01)
        assert not putter.done() and b.stats.blocked_waits == 1
        assert await b.get() == 1
        await putter
        assert b.depth == 1
    asyncio.run(run())


def test_live_source_is_a_template_not_a_fake():
    from nextrace.modules.capture.sources import LiveCaptureSource

    src = LiveCaptureSource("eth0", SID)
    h = src.health()
    assert h.source_kind == "live" and h.drop_counters_available is False
    with pytest.raises(NotImplementedError):
        src._reader()
