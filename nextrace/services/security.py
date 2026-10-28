"""Pseudonymisation, API-key hashing, log redaction and filename safety."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from ipaddress import ip_address

from nextrace.config import get_settings


class AuthorizationError(PermissionError):
    pass


def pseudonymize_ip(ip: str, pepper: str | None = None) -> bytes:
    """HMAC-SHA256 of the canonical IP. Stable for joins and exports, not reversible without the pepper.
    Raw IPs stay searchable in `flows`; the pseudonym is what leaves the system (explanations, exports)."""
    key = (pepper if pepper is not None else get_settings().pseudonym_pepper.get_secret_value()).encode()
    canonical = str(ip_address(ip)).encode()
    return hmac.new(key, canonical, hashlib.sha256).digest()


def new_api_key() -> tuple[str, bytes]:
    """Returns (raw key to hand to the caller once, sha256 digest to store)."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_api_key(raw)


def hash_api_key(raw: str) -> bytes:
    return hashlib.sha256(raw.encode()).digest()


_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._ -]{1,200}$")


def safe_filename(name: str) -> str:
    """Accept only a conservative character set; strip directory components."""
    base = name.replace("\\", "/").split("/")[-1]
    if not _SAFE_FILENAME.match(base) or base in {".", ".."} or ".." in base:
        raise ValueError("unsafe filename")
    return base


_SECRET_PATTERNS = [
    re.compile(r"(postgresql(?:\+\w+)?://[^:/\s]+:)[^@\s]+@", re.I),
    re.compile(r"(redis://[^:/\s]*:)[^@\s]+@", re.I),
    re.compile(r"((?:pepper|password|api[_-]?key|token|secret)\s*[=:]\s*)\S+", re.I),
]


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(r"\1<redacted>", text)
    return text


class RedactingFilter(logging.Filter):
    """Attach to every handler: logging.getLogger().addFilter(RedactingFilter())."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if record.args:
            record.args = tuple(redact(str(a)) for a in record.args)
        return True
