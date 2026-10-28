"""Header-only packet decoding. Payload bytes are measured, never copied out of this function."""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import UUID

from nextrace.contracts.observations import PacketObservationV1

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
ETH_IPV4, ETH_IPV6, ETH_VLAN = 0x0800, 0x86DD, 0x8100


def decode(ts: float, data: bytes, wirelen: int, link_type: int, sensor_id: UUID, segment_id: UUID | None = None) -> PacketObservationV1:
    """Pure-Python decode of Ethernet/VLAN/IPv4/IPv6/TCP/UDP headers. Anything unexpected is marked malformed,
    never raised: a hostile packet must not take the capture loop down."""
    obs: dict = {"ts": datetime.fromtimestamp(ts, tz=timezone.utc), "sensor_id": sensor_id, "link_type": link_type,
                 "caplen": len(data), "wirelen": max(wirelen, len(data)), "pcap_segment_id": segment_id,
                 "truncated": wirelen > len(data)}
    try:
        off = 0
        if link_type == LINKTYPE_ETHERNET:
            if len(data) < 14:
                raise ValueError("short ethernet")
            eth = int.from_bytes(data[12:14], "big")
            off = 14
            while eth == ETH_VLAN:
                if len(data) < off + 4:
                    raise ValueError("short vlan")
                eth = int.from_bytes(data[off + 2:off + 4], "big")
                off += 4
            if eth not in (ETH_IPV4, ETH_IPV6):
                obs["payload_len"] = max(0, len(data) - off)
                return PacketObservationV1(**obs)  # non-IP frame: counted, not malformed
        elif link_type == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                raise ValueError("short sll")
            eth = int.from_bytes(data[14:16], "big")
            off = 16
            if eth not in (ETH_IPV4, ETH_IPV6):
                obs["payload_len"] = max(0, len(data) - off)
                return PacketObservationV1(**obs)
        elif link_type == LINKTYPE_RAW:
            off = 0
        else:
            obs["payload_len"] = len(data)
            return PacketObservationV1(**obs)

        if len(data) < off + 1:
            raise ValueError("no ip header")
        ver = data[off] >> 4
        if ver == 4:
            if len(data) < off + 20:
                raise ValueError("short ipv4")
            ihl = (data[off] & 0x0F) * 4
            if ihl < 20 or len(data) < off + ihl:
                raise ValueError("bad ihl")
            total_len = int.from_bytes(data[off + 2:off + 4], "big")
            proto = data[off + 9]
            src = ip_address(data[off + 12:off + 16])
            dst = ip_address(data[off + 16:off + 20])
            l4 = off + ihl
            l3_end = off + min(total_len, len(data) - off) if total_len >= ihl else len(data)
        elif ver == 6:
            if len(data) < off + 40:
                raise ValueError("short ipv6")
            payload_len = int.from_bytes(data[off + 4:off + 6], "big")
            proto = data[off + 6]
            src = ip_address(data[off + 8:off + 24])
            dst = ip_address(data[off + 24:off + 40])
            l4 = off + 40
            l3_end = min(l4 + payload_len, len(data))
        else:
            raise ValueError("unknown ip version")
        obs.update(src_ip=src, dst_ip=dst, proto=proto)
        if proto == 6 and len(data) >= l4 + 20:
            doff = (data[l4 + 12] >> 4) * 4
            obs.update(src_port=int.from_bytes(data[l4:l4 + 2], "big"), dst_port=int.from_bytes(data[l4 + 2:l4 + 4], "big"),
                       tcp_flags=data[l4 + 13], payload_len=max(0, l3_end - (l4 + doff)))
        elif proto == 17 and len(data) >= l4 + 8:
            obs.update(src_port=int.from_bytes(data[l4:l4 + 2], "big"), dst_port=int.from_bytes(data[l4 + 2:l4 + 4], "big"),
                       payload_len=max(0, l3_end - (l4 + 8)))
        elif proto in (6, 17):
            raise ValueError("short transport header")
        else:
            obs["payload_len"] = max(0, l3_end - l4)
        return PacketObservationV1(**obs)
    except (ValueError, IndexError):
        obs.update(malformed=True, payload_len=0, src_ip=None, dst_ip=None, proto=None, src_port=None, dst_port=None, tcp_flags=None)
        return PacketObservationV1(**obs)
