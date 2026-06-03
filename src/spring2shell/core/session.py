"""
Session factory and stealth delay helpers for spring2shell.
"""

from __future__ import annotations

import random
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from spring2shell.utils.network import RETRY_PROFILES, ssl_verify


def create_stealth_session(profile: str = "default") -> requests.Session:
    """Create a requests Session configured for the given reliability profile.

    Automatically applies auth credentials and proxy from
    :mod:`spring2shell.utils.auth` if configured.

    Args:
        profile: One of ``"default"``, ``"safe-audit"``, ``"aggressive"``.
                 Unknown profiles fall back to ``"default"``.

    Returns:
        Configured :class:`requests.Session` instance.
    """
    # Short-circuit to dry-run session if enabled
    try:
        from spring2shell.utils.dry_run import DryRunSession, is_dry_run

        if is_dry_run():
            return DryRunSession()  # type: ignore[return-value]
    except ImportError:
        pass

    session = requests.Session()
    session.verify = ssl_verify()

    cfg = RETRY_PROFILES.get(profile, RETRY_PROFILES["default"])
    retry_strategy = Retry(
        total=cfg["total"],
        backoff_factor=cfg["backoff_factor"],
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=cfg["pool_connections"],
        pool_maxsize=cfg["pool_maxsize"],
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = 0

    # Apply auth credentials and proxy (no-op if not configured)
    try:
        from spring2shell.utils.auth import apply_auth

        apply_auth(session)
    except ImportError:
        pass

    return session


def apply_stealth_delay(probability: float = 0.7, min_s: float = 0.1, max_s: float = 1.5) -> None:
    """Introduce a random inter-request delay to avoid rate-limiting.

    Args:
        probability: Probability (0–1) that a delay is applied.
        min_s:       Minimum delay in seconds.
        max_s:       Maximum delay in seconds.
    """
    if random.random() < probability:
        time.sleep(random.uniform(min_s, max_s))
