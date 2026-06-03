"""
HTTP header utilities and protocol helpers for spring2shell.

Provides:
- get_random_headers(): randomised, fingerprint-resistant header set
- protocol_hopper():    generate HTTP/HTTPS URL variants
- load_user_agents():   load rotating UA list from data/useragents/user_agents.txt
"""

from __future__ import annotations

import hashlib
import random
import time
import urllib.parse
from pathlib import Path

# ---------------------------------------------------------------------------
# User-agent list loader
# ---------------------------------------------------------------------------

_USER_AGENTS: list[str] = []

_DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "curl/8.1.2",
    "PostmanRuntime/7.32.3",
]


def load_user_agents(data_root: str | Path | None = None) -> list[str]:
    """Load user-agent strings from the flat text file.

    Falls back to a small built-in list if the file is not found.
    """
    global _USER_AGENTS
    if data_root is None:
        data_root = Path(__file__).parents[3] / "data"
    path = Path(data_root) / "useragents" / "user_agents.txt"
    try:
        agents = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        _USER_AGENTS = agents or _DEFAULT_USER_AGENTS
    except FileNotFoundError:
        _USER_AGENTS = _DEFAULT_USER_AGENTS
    return _USER_AGENTS


def _agents() -> list[str]:
    if not _USER_AGENTS:
        load_user_agents()
    return _USER_AGENTS


# ---------------------------------------------------------------------------
# Header generation
# ---------------------------------------------------------------------------


def get_random_headers() -> dict[str, str]:
    """Build a randomised, fingerprint-resistant header dictionary."""
    headers: dict[str, str] = {
        "User-Agent": random.choice(_agents()),
        "Content-Type": random.choice(
            ["application/json", "application/json; charset=utf-8", "text/json"]
        ),
        "Accept": "application/json, text/plain, */*",
        "X-Forwarded-For": (
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        ),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "X-Request-ID": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
    }
    if random.random() < 0.5:
        headers["X-Amzn-Trace-Id"] = f"Root=1-{random.getrandbits(64):x}"
    if random.random() < 0.4:
        headers["X-Forwarded-Proto"] = random.choice(["http", "https"])
    return headers


# ---------------------------------------------------------------------------
# Protocol hopping
# ---------------------------------------------------------------------------


def protocol_hopper(url: str) -> list[str]:
    """Return HTTP and HTTPS variants of *url*.

    If *url* has no scheme, both ``http://`` and ``https://`` prefixed variants
    are returned. Otherwise the complementary scheme is appended.
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        return ["http://" + url, "https://" + url]
    if parsed.scheme == "http":
        return [url, urllib.parse.urlunparse(parsed._replace(scheme="https"))]
    if parsed.scheme == "https":
        return [url, urllib.parse.urlunparse(parsed._replace(scheme="http"))]
    return [url]
