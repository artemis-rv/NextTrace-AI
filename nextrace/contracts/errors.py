"""Shared error taxonomy. Modules raise these; the API maps them to HTTP status codes without leaking detail."""
from __future__ import annotations


class NextraceError(Exception):
    """Base class. `public_message` is safe to return to a caller; details stay in logs."""

    status_code = 500
    public_message = "internal error"

    def __init__(self, message: str | None = None, **context: object):
        super().__init__(message or self.public_message)
        self.context = context


class ContractViolation(NextraceError, ValueError):
    status_code = 422
    public_message = "payload violates contract"


class NotFound(NextraceError, LookupError):
    status_code = 404
    public_message = "not found"


class Unauthorized(NextraceError):
    status_code = 401
    public_message = "authentication required"


class Forbidden(NextraceError, PermissionError):
    status_code = 403
    public_message = "forbidden"


class Conflict(NextraceError):
    status_code = 409
    public_message = "conflicting state"


class RateLimited(NextraceError):
    status_code = 429
    public_message = "rate limit exceeded"


class PayloadTooLarge(NextraceError):
    status_code = 413
    public_message = "payload too large"


class ModelUnavailable(NextraceError):
    """A model slot has no validated artifact. Callers must surface this, never fabricate output."""

    status_code = 503
    public_message = "model unavailable"


class Backpressure(NextraceError):
    """A bounded queue is full and the configured policy is to reject rather than drop or block."""

    status_code = 503
    public_message = "pipeline saturated"


class ConnectorError(NextraceError):
    status_code = 502
    public_message = "enforcement connector failed"
