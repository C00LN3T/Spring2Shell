"""
Structured logging utilities for spring2shell.

Provides:
- log_event()              — structured key=value log emission
- log_swallowed_exception()— conditional diagnostic logging
- classify_exception()     — maps exception types to taxonomy codes
- ERROR_TAXONOMY           — canonical error codes
"""

from __future__ import annotations

import logging
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Error taxonomy — canonical codes for structured log / report output
# ---------------------------------------------------------------------------
ERROR_TAXONOMY: dict[str, str] = {
    "timeout": "NET_TIMEOUT",
    "connection": "NET_CONNECTION",
    "ssl": "NET_TLS",
    "http": "HTTP_ERROR",
    "json": "PARSE_JSON",
    "unknown": "UNKNOWN",
}

# ---------------------------------------------------------------------------
# Logger instance
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("spring2shell")


def set_log_level(level: str) -> None:
    """Set the root logger level by name (e.g. 'DEBUG', 'WARNING')."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def classify_exception(exc: Exception) -> str:
    """Map an exception to a canonical ERROR_TAXONOMY code."""
    msg = str(exc).lower()
    if isinstance(exc, requests.exceptions.Timeout) or "timeout" in msg:
        return ERROR_TAXONOMY["timeout"]
    if isinstance(exc, requests.exceptions.SSLError) or "ssl" in msg or "certificate" in msg:
        return ERROR_TAXONOMY["ssl"]
    if (
        isinstance(exc, requests.exceptions.ConnectionError)
        or "connection" in msg
        or "name or service not known" in msg
    ):
        return ERROR_TAXONOMY["connection"]
    if isinstance(exc, requests.exceptions.HTTPError):
        return ERROR_TAXONOMY["http"]
    try:
        import json

        if isinstance(exc, json.JSONDecodeError):
            return ERROR_TAXONOMY["json"]
    except ImportError:
        pass
    return ERROR_TAXONOMY["unknown"]


def log_event(level: int, message: str, **context: Any) -> None:
    """Emit a structured log line with optional key=value context pairs."""
    extra = " ".join(f"{k}={v}" for k, v in context.items()) if context else ""
    logger.log(level, f"{message} {extra}".strip())


def log_swallowed_exception(context: str, exc: Exception) -> None:
    """Conditionally log a swallowed exception when verbose errors are enabled.

    Controlled by :func:`spring2shell.utils.network.is_verbose_errors`.
    """
    from spring2shell.utils.network import is_verbose_errors  # avoid circular

    if is_verbose_errors():
        reason_code = classify_exception(exc)
        log_event(logging.WARNING, f"{context}: {exc}", reason_code=reason_code)
