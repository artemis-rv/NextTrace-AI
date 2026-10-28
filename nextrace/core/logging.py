"""Structured JSON logging with secret redaction and CR/LF sanitisation (OWASP Logging Cheat Sheet)."""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

from nextrace.services.security import RedactingFilter, redact

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
actor_var: ContextVar[str | None] = ContextVar("actor", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()).replace("\r", "\\r").replace("\n", "\\n"),
        }
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid
        actor = actor_var.get()
        if actor:
            payload["actor"] = actor
        for key in ("module_name", "stage", "sensor_id", "object_id", "event"):
            if hasattr(record, key):
                payload[key] = str(getattr(record, key))
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))[-4000:]
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json_output else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("uvicorn.access").disabled = True  # access lines carry query strings; the API logs its own summary


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
