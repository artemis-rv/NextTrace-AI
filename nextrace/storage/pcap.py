"""PCAP segment registry: headers-only ring, short full-payload ring, uploads, and evidence carving.

Packets are never stored as relational rows. Capture files are content-addressed objects; the
`pcap_segments` table indexes them by sensor and time so a slice can be carved for a case.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator
from uuid import UUID

from scapy.utils import RawPcapNgReader, RawPcapReader
from sqlalchemy import text
from sqlalchemy.engine import Connection

from nextrace.storage.object_store import LocalObjectStore, ObjectRef

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MEDIA_TYPE = "application/vnd.tcpdump.pcap"


@dataclass(frozen=True)
class SegmentInfo:
    ts_first: datetime
    ts_last: datetime
    packet_count: int
    link_type: int | None


def iter_packets(path: Path) -> Iterator[tuple[float, bytes, int, int | None]]:
    """Yield (epoch_seconds, captured_bytes, wire_length, link_type) from a pcap or pcapng file."""
    reader = RawPcapReader(str(path))  # metaclass dispatches to RawPcapNgReader for pcapng
    try:
        if isinstance(reader, RawPcapNgReader):
            for data, meta in reader:
                ts = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol
                yield ts, data, meta.wirelen, meta.linktype
        else:
            div = 1e9 if getattr(reader, "nano", False) else 1e6
            lt = reader.linktype
            for data, meta in reader:
                yield meta.sec + meta.usec / div, data, meta.wirelen, lt
    finally:
        reader.close()


def scan(path: Path) -> SegmentInfo:
    first = last = None
    n = 0
    lt = None
    for ts, _, _, link in iter_packets(path):
        n += 1
        lt = link if lt is None else lt
        first = ts if first is None or ts < first else first
        last = ts if last is None or ts > last else last
    if n == 0:
        raise ValueError("capture file contains no packets")
    return SegmentInfo(datetime.fromtimestamp(first, timezone.utc), datetime.fromtimestamp(last, timezone.utc), n, lt)


class PcapWriter:
    """Minimal classic pcap writer (microsecond timestamps). Used for carved evidence slices."""

    def __init__(self, out: BinaryIO, link_type: int, snaplen: int = 262144):
        self.out = out
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC_USEC, 2, 4, 0, 0, snaplen, link_type))

    def write(self, ts: float, data: bytes, wirelen: int) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        self.out.write(struct.pack("<IIII", sec, usec, len(data), wirelen))
        self.out.write(data)


def register_segment(conn: Connection, store: LocalObjectStore, sensor_id: UUID, path: Path, capture_kind: str,
                     snaplen: int | None = None) -> tuple[UUID, ObjectRef]:
    """Hash the file into the object store and index it. Returns (segment_id, object ref)."""
    if capture_kind not in {"headers", "full", "upload"}:
        raise ValueError("capture_kind must be headers, full or upload")
    info = scan(path)
    ref = store.put_path(path, "pcap")
    conn.execute(text(
        "INSERT INTO objects (sha256, size_bytes, media_type, kind, storage_path) VALUES (:h, :s, :m, 'pcap', :p) "
        "ON CONFLICT (sha256) DO NOTHING"), {"h": ref.sha256, "s": ref.size_bytes, "m": PCAP_MEDIA_TYPE, "p": ref.storage_path})
    seg_id = conn.execute(text(
        "INSERT INTO pcap_segments (sensor_id, capture_kind, snaplen, link_type, ts_first, ts_last, packet_count, object_sha256) "
        "VALUES (:sid, :kind, :snap, :lt, :f, :l, :n, :h) RETURNING segment_id"),
        {"sid": sensor_id, "kind": capture_kind, "snap": snaplen, "lt": info.link_type, "f": info.ts_first,
         "l": info.ts_last, "n": info.packet_count, "h": ref.sha256}).scalar_one()
    return seg_id, ref


def segments_overlapping(conn: Connection, sensor_id: UUID | None, start: datetime, end: datetime,
                         kinds: tuple[str, ...] = ("headers", "full", "upload")) -> list[dict]:
    rows = conn.execute(text(
        "SELECT s.segment_id, s.sensor_id, s.capture_kind, s.link_type, o.sha256, o.size_bytes, o.storage_path "
        "FROM pcap_segments s JOIN objects o ON o.sha256 = s.object_sha256 "
        "WHERE s.status <> 'reclaimed' AND o.deleted_at IS NULL AND s.ts_last >= :start AND s.ts_first <= :end "
        "AND (CAST(:sid AS uuid) IS NULL OR s.sensor_id = :sid) AND s.capture_kind = ANY(:kinds) ORDER BY s.ts_first"),
        {"start": start, "end": end, "sid": sensor_id, "kinds": list(kinds)}).mappings().all()
    return [dict(r) for r in rows]


def carve(store: LocalObjectStore, segments: list[dict], start: datetime, end: datetime, out: BinaryIO) -> int:
    """Write every packet with start <= ts < end from the given segments into `out` (classic pcap).
    Returns the packet count. Segments are verified against their recorded hash before reading."""
    t0, t1 = start.timestamp(), end.timestamp()
    writer: PcapWriter | None = None
    n = 0
    for seg in segments:
        ref = ObjectRef(bytes(seg["sha256"]), int(seg["size_bytes"]), seg["storage_path"])
        if not store.verify(ref):
            raise RuntimeError(f"pcap segment {seg['segment_id']} failed integrity verification")
        for ts, data, wirelen, lt in iter_packets(store.root / ref.storage_path):
            if ts < t0 or ts >= t1:
                continue
            if writer is None:
                writer = PcapWriter(out, lt if lt is not None else 1)
            writer.write(ts, data, wirelen)
            n += 1
    if writer is None:
        PcapWriter(out, 1)  # empty but valid file
    return n
