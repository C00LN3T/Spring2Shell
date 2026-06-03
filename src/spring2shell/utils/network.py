"""
Network-level globals and runtime configuration for spring2shell.

Centralises SSL verification flag, verbose-errors flag, and retry/timeout
profiles that were previously hardcoded constants in the monolith.
Config values are loaded from configs/default.yaml (and optionally an active
profile) at startup via :func:`load_config`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import urllib3

# ---------------------------------------------------------------------------
# Module-level runtime flags (mutated by configure_runtime())
# ---------------------------------------------------------------------------
_SSL_VERIFY: bool = True
_LOG_EXCEPTIONS: bool = False

# ---------------------------------------------------------------------------
# Default fallbacks used when YAML config is not yet loaded
# ---------------------------------------------------------------------------
RETRY_PROFILES: dict[str, dict[str, Any]] = {
    "default": {
        "total": 3,
        "backoff_factor": 0.4,
        "pool_connections": 8,
        "pool_maxsize": 16,
    },
    "safe-audit": {
        "total": 2,
        "backoff_factor": 0.2,
        "pool_connections": 6,
        "pool_maxsize": 12,
    },
    "aggressive": {
        "total": 4,
        "backoff_factor": 0.5,
        "pool_connections": 10,
        "pool_maxsize": 20,
    },
}

TIMEOUT_PROFILES: dict[str, float] = {
    "default": 6.0,
    "safe-audit": 5.0,
    "aggressive": 8.0,
}


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------


def ssl_verify() -> bool:
    """Return the current TLS verification setting."""
    return _SSL_VERIFY


def is_verbose_errors() -> bool:
    """Return True if swallowed exceptions should be logged."""
    return _LOG_EXCEPTIONS


# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------


def configure_runtime(insecure: bool = False, verbose_errors: bool = False) -> None:
    """Apply global runtime security settings.

    Args:
        insecure:       Disable TLS certificate verification (not recommended).
        verbose_errors: Log swallowed network exceptions for diagnostics.
    """
    global _SSL_VERIFY, _LOG_EXCEPTIONS
    _SSL_VERIFY = not insecure
    _LOG_EXCEPTIONS = verbose_errors

    from spring2shell.utils.logging import log_event  # avoid circular at module load

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log_event(logging.WARNING, "TLS certificate verification is disabled (--insecure)")
    else:
        import warnings

        warnings.filterwarnings("default", category=urllib3.exceptions.InsecureRequestWarning)


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load YAML config, merging default with an optional profile override.

    Returns the merged config dict. Falls back gracefully if PyYAML is not
    installed or the file does not exist.
    """
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        return {}

    default_path = Path(__file__).parents[3] / "configs" / "default.yaml"
    config: dict[str, Any] = {}

    if default_path.exists():
        with default_path.open() as fh:
            config = yaml.safe_load(fh) or {}

    if config_path:
        profile_path = Path(config_path)
        if profile_path.exists():
            with profile_path.open() as fh:
                override = yaml.safe_load(fh) or {}
            _deep_merge(config, override)

    return config


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Recursively merge *override* into *base* in-place."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
