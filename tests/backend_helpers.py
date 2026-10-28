"""Deterministic packet/pcap fixtures for backend tests (Ethernet/IPv4/TCP+UDP, no scapy needed)."""
from __future__ import annotations

import contextlib
import struct
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import text

from nextrace.services.security import hash_api_key
from nextrace.storage.pcap import PcapWriter

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def tcp_packet(src: str, sport: int, dst: str, dport: int, flags: int, payload: bytes = b"") -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, _ip(src), _ip(dst))
    return eth + ip + tcp


def udp_packet(src: str, sport: int, dst: str, dport: int, payload: bytes = b"x" * 32) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, _ip(src), _ip(dst))
    return eth + ip + udp


def handshake(ts: float, src: str, sport: int, dst: str, dport: int, payload: bytes = b"GET / HTTP/1.1\r\n") -> list[tuple[float, bytes]]:
    return [
        (ts, tcp_packet(src, sport, dst, dport, SYN)),
        (ts + 0.01, tcp_packet(dst, dport, src, sport, SYN | ACK)),
        (ts + 0.02, tcp_packet(src, sport, dst, dport, ACK)),
        (ts + 0.03, tcp_packet(src, sport, dst, dport, ACK | PSH, payload)),
        (ts + 0.05, tcp_packet(dst, dport, src, sport, ACK | PSH, b"HTTP/1.1 200 OK\r\n" + b"a" * 200)),
        (ts + 0.06, tcp_packet(src, sport, dst, dport, FIN | ACK)),
        (ts + 0.07, tcp_packet(dst, dport, src, sport, FIN | ACK)),
    ]


def scenario_packets(base: datetime, benign_flows: int = 60, scan_ports: int = 120, beacon_count: int = 12, beacon_period_s: float = 20.0,
                     span_s: float = 120.0) -> list[tuple[float, bytes]]:
    """Benign web traffic from 10.0.0.1-5, a SYN scan from 10.0.0.99 against 10.0.1.20 (no replies), and a beacon 10.0.0.7 -> 203.0.113.5."""
    t0 = base.timestamp()
    pkts: list[tuple[float, bytes]] = []
    for i in range(benign_flows):
        ts = t0 + (i / benign_flows) * span_s
        pkts += handshake(ts, f"10.0.0.{(i % 5) + 1}", 40000 + i, "10.0.1.10", 80 if i % 2 else 443)
    scan_start = t0 + span_s * 0.4
    for i in range(scan_ports):
        pkts.append((scan_start + i * 0.02, tcp_packet("10.0.0.99", 50000 + i, "10.0.1.20", 1 + i, SYN)))
    for i in range(beacon_count):
        pkts += handshake(t0 + i * beacon_period_s, "10.0.0.7", 42000 + i, "203.0.113.5", 443, b"\x16\x03\x01" + b"\x00" * 40)
    pkts.append((t0 + 1.0, udp_packet("10.0.0.3", 5353, "10.0.1.53", 53)))
    pkts.sort(key=lambda p: p[0])
    return pkts


def write_pcap(path: Path, packets: list[tuple[float, bytes]], link_type: int = 1) -> Path:
    with open(path, "wb") as fh:
        w = PcapWriter(fh, link_type=link_type)
        for ts, data in packets:
            w.write(ts, data, len(data))
    return path


def make_user(conn, role: str, with_key: bool = True) -> tuple[uuid.UUID, str | None]:
    raw = f"key-{uuid.uuid4().hex}" if with_key else None
    uid = conn.execute(text("INSERT INTO users (username, role, api_key_hash) VALUES (:u, :r, :h) RETURNING user_id"),
                       {"u": f"{role}-{uuid.uuid4().hex[:8]}", "r": role, "h": hash_api_key(raw) if raw else None}).scalar_one()
    return uid, raw


def make_sensor(conn, kind: str = "pcap_upload") -> uuid.UUID:
    return conn.execute(text("INSERT INTO sensors (name, kind) VALUES (:n, :k) RETURNING sensor_id"), {"n": f"s-{uuid.uuid4().hex[:8]}", "k": kind}).scalar_one()


@contextlib.contextmanager
def savepoint(conn):
    with conn.begin_nested():
        yield conn


def an_hour_ago() -> datetime:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0)
