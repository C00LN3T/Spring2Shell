"""
Signal handling for spring2shell.

Registers a SIGINT handler so Ctrl-C produces a clean shutdown message
instead of a traceback, and exposes :func:`is_interrupted` for polling
in scan loops.
"""

from __future__ import annotations

import signal

_interrupted: bool = False


def is_interrupted() -> bool:
    """Return True if a SIGINT has been received."""
    return _interrupted


def _handler(sig: int, frame: object) -> None:
    global _interrupted
    _interrupted = True
    print("\n[!] Received interrupt signal. Stopping scan…")


def register() -> None:
    """Register the SIGINT handler. Call once at startup."""
    signal.signal(signal.SIGINT, _handler)
