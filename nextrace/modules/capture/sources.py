"""Capture sources implementing contracts.ports.CaptureSource.

PcapReplaySource is the controlled local fixture every other module tests against. LiveCaptureSource is a
typed template: the structure (reader thread -> bounded queue -> async batches, drop counters, backpressure)
is in place; the privileged socket code is the Person 4 extension point.
"""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Literal
from uuid import UUID

from nextrace.contracts.observations import CaptureHealthV1, FlowBatchV1
from nextrace.contracts.v1 import FlowRecordV1
from nextrace.core.bus import BoundedQueue, Policy
from nextrace.parsing.decode import decode
from nextrace.parsing.flows import FlowAssembler
from nextrace.storage import pcap as pcapmod


@dataclass
class _Counters:
    packets_seen: int = 0
    packets_malformed: int = 0
    packets_truncated: int = 0
    bytes_seen: int = 0
    flows_emitted: int = 0
    batches: int = 0
    backpressure_events: int = 0
    shed_flows: int = 0
    last_packet_ts: datetime | None = None


class PcapReplaySource:
    """Replays a pcap/pcapng file as ordered FlowBatchV1 messages. `realtime=False` replays as fast as the consumer accepts."""

    def __init__(self, path: Path, sensor_id: UUID, batch_flows: int = 500, realtime: bool = False, speed: float = 1.0,
                 assembler: FlowAssembler | None = None, segment_id: UUID | None = None):
        self.path = Path(path)
        self.sensor_id = sensor_id
        self.batch_flows = max(1, batch_flows)
        self.realtime = realtime
        self.speed = speed
        self.assembler = assembler or FlowAssembler()
        self.segment_id = segment_id
        self.c = _Counters()
        self._seq = 0
        self._stop = False
        self.info = pcapmod.scan(self.path)

    def _batch(self, flows: list[FlowRecordV1]) -> FlowBatchV1:
        flows.sort(key=lambda f: f.ts_start)
        b = FlowBatchV1(sensor_id=self.sensor_id, batch_seq=self._seq, produced_at=datetime.now(timezone.utc),
                        source="pcap_replay", flows=flows, pcap_segment_id=self.segment_id)
        self._seq += 1
        self.c.batches += 1
        self.c.flows_emitted += len(flows)
        return b

    async def batches(self) -> AsyncIterator[FlowBatchV1]:
        pending: list[FlowRecordV1] = []
        wall0 = time.monotonic()
        t0: float | None = None
        n = 0
        for ts, data, wirelen, link in pcapmod.iter_packets(self.path):
            if self._stop:
                break
            obs = decode(ts, data, wirelen, link if link is not None else self.info.link_type, self.sensor_id, self.segment_id)
            self.c.packets_seen += 1
            self.c.bytes_seen += wirelen
            self.c.last_packet_ts = obs.ts
            if obs.malformed:
                self.c.packets_malformed += 1
            if obs.truncated:
                self.c.packets_truncated += 1
            pending.extend(self.assembler.feed(obs))
            if self.realtime:
                t0 = ts if t0 is None else t0
                target = wall0 + (ts - t0) / self.speed
                delay = target - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
            n += 1
            if len(pending) >= self.batch_flows:
                yield self._batch(pending)
                pending = []
            elif n % 2000 == 0:
                await asyncio.sleep(0)  # keep the loop responsive on long files
        pending.extend(self.assembler.flush())
        if pending:
            yield self._batch(pending)

    def health(self) -> CaptureHealthV1:
        return CaptureHealthV1(
            sensor_id=self.sensor_id, at=datetime.now(timezone.utc), source_kind="pcap_replay", interface=None,
            packets_seen=self.c.packets_seen, packets_malformed=self.c.packets_malformed, packets_truncated=self.c.packets_truncated,
            bytes_seen=self.c.bytes_seen, flows_emitted=self.c.flows_emitted, kernel_drops=None, interface_drops=None,
            drop_counters_available=False, queue_depth=0, queue_capacity=1, backpressure_events=self.c.backpressure_events,
            shed_flows=self.c.shed_flows, last_packet_ts=self.c.last_packet_ts, clock_skew_s=None)

    async def stop(self) -> None:
        self._stop = True


class LiveCaptureSource:
    """Template for a privileged live capture (owner: Person 4).

    Design that is already fixed by this template and must not change without a contract review:
      * a reader thread decodes headers only and calls `self._queue.put_nowait(batch)`; the queue policy for live
        capture is `shed_oldest` so a slow consumer never stalls the kernel ring, and every shed batch is counted;
      * `pcap_stats`-style drop counters are reported through CaptureHealthV1 with `drop_counters_available`
        set honestly (libpcap: ps_drop/ps_ifdrop may be unavailable and read as zero);
      * capture never writes to the database; it only emits FlowBatchV1 and, when configured, writes rolling
        pcap segments through storage.pcap.register_segment via the pipeline.

    TODO(PERSON4): implement `_reader()` with the platform socket (AF_PACKET/TPACKET_V3 on Linux via libpcap or
    scapy.conf.L2listen; Npcap on Windows), fill `_drops()` from the handle's statistics, and add a snaplen
    option so only headers are captured when full PCAP retention is not authorised.
    """

    def __init__(self, interface: str, sensor_id: UUID, queue_capacity: int = 256, policy: Policy = "shed_oldest",
                 batch_flows: int = 500, assembler: FlowAssembler | None = None):
        self.interface = interface
        self.sensor_id = sensor_id
        self.assembler = assembler or FlowAssembler()
        self.batch_flows = batch_flows
        self._queue: BoundedQueue[FlowBatchV1] = BoundedQueue(f"capture.{sensor_id}", queue_capacity, policy)
        self.c = _Counters()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._seq = 0

    def _drops(self) -> tuple[int | None, int | None, bool]:
        return None, None, False  # TODO(PERSON4): return (ps_drop, ps_ifdrop, True) from the live handle

    def _reader(self) -> None:  # pragma: no cover - template
        raise NotImplementedError("TODO(PERSON4): live socket reader not implemented; use PcapReplaySource for testing")

    async def batches(self) -> AsyncIterator[FlowBatchV1]:
        if self._thread is None:
            self._thread = threading.Thread(target=self._reader, name=f"capture-{self.interface}", daemon=True)
            self._thread.start()
        while not self._stop_event.is_set():
            item = await self._queue.get(timeout_s=1.0)
            if item is not None:
                yield item

    def health(self) -> CaptureHealthV1:
        kd, ifd, avail = self._drops()
        return CaptureHealthV1(
            sensor_id=self.sensor_id, at=datetime.now(timezone.utc), source_kind="live", interface=self.interface,
            packets_seen=self.c.packets_seen, packets_malformed=self.c.packets_malformed, packets_truncated=self.c.packets_truncated,
            bytes_seen=self.c.bytes_seen, flows_emitted=self.c.flows_emitted, kernel_drops=kd, interface_drops=ifd,
            drop_counters_available=avail, queue_depth=self._queue.depth, queue_capacity=self._queue.capacity,
            backpressure_events=self._queue.stats.blocked_waits + self._queue.stats.rejected, shed_flows=self._queue.stats.shed,
            last_packet_ts=self.c.last_packet_ts, clock_skew_s=None)

    async def stop(self) -> None:
        self._stop_event.set()
        self._queue.close()


SourceKind = Literal["pcap_replay", "live"]
