"""UUIDv7 (RFC 9562) generation for ids minted outside the database, so they sort with DB-minted ones."""
from __future__ import annotations

import os
import time
import uuid

_last_ms = 0
_seq = 0


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    global _last_ms, _seq
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    if ms == _last_ms:
        _seq = (_seq + 1) & 0xFFF
    else:
        _last_ms, _seq = ms, int.from_bytes(os.urandom(2), "big") & 0xFFF
    rand = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (ms & ((1 << 48) - 1)) << 80 | 0x7 << 76 | _seq << 64 | 0b10 << 62 | rand
    return uuid.UUID(int=value)
