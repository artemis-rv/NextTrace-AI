"""Case-level authorization, evidence provenance and custody, PCAP carving."""
import struct
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from nextrace.services import investigations as inv
from nextrace.services.security import AuthorizationError
from nextrace.storage import pcap as pcapmod
from tests.conftest import NOW

T0 = NOW - timedelta(minutes=30)


def _write_pcap(path, n, start, link_type=1, step_s=1.0):
    """n Ethernet/IPv4-looking frames, `step_s` apart, using the project's own writer."""
    with open(path, "wb") as f:
        w = pcapmod.PcapWriter(f, link_type)
        for i in range(n):
            payload = b"\x00" * 12 + b"\x08\x00" + bytes([0x45]) + b"\x00" * 19 + struct.pack(">I", i) + b"\x00" * 40
            w.write(start.timestamp() + i * step_s, payload, len(payload))


@pytest.fixture
def case(conn, seed):
    cid = inv.open_case(conn, "CASE-0001", "Suspicious lateral movement", "high", seed["users"]["dfir"])
    return cid


def test_grants_are_role_bound_and_expire(conn, seed, case):
    u = seed["users"]
    with pytest.raises(AuthorizationError):
        inv.grant_access(conn, case, u["analyst"], "metadata", u["analyst2"], NOW + timedelta(days=1), "peer grant not allowed")
    with pytest.raises(IntegrityError):  # cannot grant yourself
        with conn.begin_nested():
            inv.grant_access(conn, case, u["dfir"], "metadata", u["dfir"], NOW + timedelta(days=1), "self grant")
    inv.grant_access(conn, case, u["analyst"], "metadata", u["dfir"], NOW + timedelta(days=1), "triage of CASE-0001")
    assert inv.has_access(conn, u["analyst"], case, "metadata")
    assert not inv.has_access(conn, u["analyst"], case, "full_pcap")
    assert not inv.has_access(conn, u["viewer"], case, "metadata")
    assert inv.has_access(conn, u["admin"], case, "metadata") and not inv.has_access(conn, u["admin"], case, "full_pcap")
    gid = conn.execute(text("SELECT grant_id FROM case_grants WHERE user_id = :u"), {"u": u["analyst"]}).scalar_one()
    inv.revoke_access(conn, gid, u["dfir"])
    assert not inv.has_access(conn, u["analyst"], case, "metadata")
    conn.execute(text("UPDATE case_grants SET revoked_at = NULL, granted_at = now() - interval '2 days', "
                      "expires_at = now() - interval '1 second' WHERE grant_id = :g"), {"g": gid})
    assert not inv.has_access(conn, u["analyst"], case, "metadata")


def test_evidence_lifecycle_and_full_pcap_gate(conn, seed, case, store, tmp_path):
    u = seed["users"]
    inv.grant_access(conn, case, u["analyst"], "metadata", u["dfir"], NOW + timedelta(days=1), "triage of CASE-0001")
    inv.grant_access(conn, case, u["dfir"], "full_pcap", u["admin"], NOW + timedelta(days=1), "lead investigator")
    p = tmp_path / "cap.pcap"
    _write_pcap(p, 5, T0)
    ref = store.put_path(p, "pcap")
    eid = inv.add_evidence(conn, case, ref, "pcap_slice", pcapmod.PCAP_MEDIA_TYPE, "sensor capture", u["dfir"], "manual upload")

    with pytest.raises(AuthorizationError):
        inv.open_evidence(conn, store, eid, u["analyst"])      # metadata grant is not enough for packets
    with pytest.raises(AuthorizationError):
        inv.open_evidence(conn, store, eid, u["viewer"])
    denied = conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'case.access_denied'")).scalar_one()
    assert denied == 2
    got = inv.open_evidence(conn, store, eid, u["dfir"])
    assert got.sha256 == ref.sha256
    assert inv.verify_evidence(conn, store, eid, u["analyst"]) is True
    actions = list(conn.execute(text("SELECT action FROM custody_events WHERE evidence_id = :e ORDER BY at, event_id"), {"e": eid}).scalars())
    assert actions == ["acquired", "accessed", "verified"]
    with pytest.raises(IntegrityError, match="append-only"):
        with conn.begin_nested():
            conn.execute(text("DELETE FROM custody_events WHERE evidence_id = :e"), {"e": eid})

    # Tamper with the stored bytes: verification fails and access is refused.
    target = store.root / ref.storage_path
    import os, stat
    os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
    with open(target, "r+b") as f:
        f.seek(30)
        f.write(b"\xff")
    assert inv.verify_evidence(conn, store, eid, u["dfir"]) is False
    with pytest.raises(RuntimeError, match="integrity"):
        inv.open_evidence(conn, store, eid, u["dfir"])
    assert conn.execute(text("SELECT verify_ok FROM objects WHERE sha256 = :h"), {"h": ref.sha256}).scalar_one() is False


def test_carve_pcap_slice_from_registered_segments(conn, seed, case, store, tmp_path):
    u = seed["users"]
    inv.grant_access(conn, case, u["dfir"], "full_pcap", u["admin"], NOW + timedelta(days=1), "lead investigator")
    p1, p2 = tmp_path / "a.pcap", tmp_path / "b.pcap"
    _write_pcap(p1, 60, T0)                                   # T0 .. T0+59s
    _write_pcap(p2, 60, T0 + timedelta(seconds=60))           # T0+60 .. T0+119s
    s1, _ = pcapmod.register_segment(conn, store, seed["sensor_id"], p1, "headers", snaplen=96)
    s2, _ = pcapmod.register_segment(conn, store, seed["sensor_id"], p2, "headers", snaplen=96)
    seg = conn.execute(text("SELECT packet_count, ts_first, ts_last FROM pcap_segments WHERE segment_id = :s"), {"s": s1}).one()
    assert seg.packet_count == 60 and seg.ts_first == T0

    start, end = T0 + timedelta(seconds=50), T0 + timedelta(seconds=70)
    eid = inv.carve_pcap_evidence(conn, store, case, seed["sensor_id"], start, end, u["dfir"], "slice around alert")
    ref = inv.open_evidence(conn, store, eid, u["dfir"])
    out = tmp_path / "slice.pcap"
    store.copy_out(ref, out)
    info = pcapmod.scan(out)
    assert info.packet_count == 20 and info.ts_first == start and info.ts_last == end - timedelta(seconds=1)
    method = conn.execute(text("SELECT acquisition_method FROM evidence_items WHERE evidence_id = :e"), {"e": eid}).scalar_one()
    assert method.startswith("carved 20 packets from 2")
    with pytest.raises(AuthorizationError):
        inv.carve_pcap_evidence(conn, store, case, seed["sensor_id"], start, end, u["analyst"], "no grant")


def test_pcapng_is_readable(tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcapng
    pkts = []
    for i in range(3):
        pk = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80)
        pk.time = T0.timestamp() + i
        pkts.append(pk)
    wrpcapng(str(tmp_path / "c.pcapng"), pkts)
    info = pcapmod.scan(tmp_path / "c.pcapng")
    assert info.packet_count == 3 and info.ts_first == T0 and info.link_type == 1
