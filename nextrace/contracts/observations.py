"""Capture-side contracts (owner: central contracts; producer: Person 4 live capture module).

Packet observations never carry payload bytes across module boundaries: only decoded header fields and a
reference to the retained capture segment. Flows reuse `FlowRecordV1` (storage contract) so capture,
historical ingestion and forensics all speak one flow format.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from nextrace.contracts.v1 import FlowRecordV1, IPAddress, _aware, _Contract


class PacketObservationV1(_Contract):
    """Decoded headers of one captured packet. `payload_len` is recorded, payload bytes are not."""

    ts: datetime
    sensor_id: UUID
    link_type: int = Field(ge=0, le=65535)
    caplen: int = Field(ge=0, le=262144)
    wirelen: int = Field(ge=0, le=262144)
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None
    proto: int | None = Field(default=None, ge=0, le=255)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    tcp_flags: int | None = Field(default=None, ge=0, le=255)
    payload_len: int = Field(default=0, ge=0)
    truncated: bool = False
    malformed: bool = False
    pcap_segment_id: UUID | None = None

    @field_validator("ts")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _lens(self) -> "PacketObservationV1":
        if self.caplen > self.wirelen:
            raise ValueError("caplen exceeds wirelen")
        return self


class CaptureHealthV1(_Contract):
    """Periodic health report from a capture source. Zero drop counters are not proof of no loss:
    libpcap documents ps_drop/ps_ifdrop as unavailable (reported as zero) on some platforms."""

    sensor_id: UUID
    at: datetime
    source_kind: Literal["live", "pcap_replay", "pcapng_replay"]
    interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:/\\{}-]{1,128}$")
    packets_seen: int = Field(ge=0)
    packets_malformed: int = Field(ge=0)
    packets_truncated: int = Field(ge=0)
    bytes_seen: int = Field(ge=0)
    flows_emitted: int = Field(ge=0)
    kernel_drops: int | None = Field(default=None, ge=0, description="pcap_stats ps_drop; None when unavailable")
    interface_drops: int | None = Field(default=None, ge=0, description="pcap_stats ps_ifdrop; None when unavailable")
    drop_counters_available: bool = False
    queue_depth: int = Field(ge=0)
    queue_capacity: int = Field(ge=1)
    backpressure_events: int = Field(ge=0)
    shed_flows: int = Field(ge=0, description="flows dropped by the capture module under 'shed' policy")
    last_packet_ts: datetime | None = None
    clock_skew_s: float | None = Field(default=None, description="capture clock minus wall clock at report time")

    @field_validator("at", "last_packet_ts")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _aware(v)

    @model_validator(mode="after")
    def _depth(self) -> "CaptureHealthV1":
        if self.queue_depth > self.queue_capacity:
            raise ValueError("queue_depth exceeds capacity")
        return self


class FlowBatchV1(_Contract):
    """What the capture module hands to the central pipeline: normalized flows plus provenance.
    Ordered by ts_start within the batch; the sequencer tolerates late flows across batches."""

    sensor_id: UUID
    batch_seq: int = Field(ge=0, description="monotonic per sensor process; gaps mean loss")
    produced_at: datetime
    source: Literal["live_capture", "pcap_replay", "zeek_conn", "suricata_eve", "csv"]
    flows: list[FlowRecordV1] = Field(max_length=50_000)
    pcap_segment_id: UUID | None = None

    @field_validator("produced_at")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _aware(v)

    @model_validator(mode="after")
    def _ordered(self) -> "FlowBatchV1":
        for a, b in zip(self.flows, self.flows[1:]):
            if b.ts_start < a.ts_start:
                raise ValueError("flows within a batch must be ordered by ts_start")
        return self
