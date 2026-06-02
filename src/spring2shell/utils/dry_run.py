"""
Dry-run mode for spring2shell.

When enabled, all HTTP requests are intercepted and printed to stdout
instead of being sent to the network. Useful for reviewing payloads
before live testing.

Usage:
    from spring2shell.utils.dry_run import enable_dry_run, is_dry_run, DryRunSession
"""

from __future__ import annotations

import urllib.parse
from typing import Any
from unittest.mock import MagicMock

_DRY_RUN: bool = False


def enable_dry_run() -> None:
    """Enable dry-run mode globally."""
    global _DRY_RUN
    _DRY_RUN = True


def disable_dry_run() -> None:
    """Disable dry-run mode (for testing)."""
    global _DRY_RUN
    _DRY_RUN = False


def is_dry_run() -> bool:
    """Return True if dry-run mode is active."""
    return _DRY_RUN


class _FakeResponse:
    """Fake requests.Response for dry-run mode."""
    status_code: int = 200
    text: str = "DRY_RUN_RESPONSE"
    content: bytes = b"DRY_RUN_RESPONSE"
    headers: dict = {}
    url: str = ""

    def json(self) -> dict:
        return {}

    def raise_for_status(self) -> None:
        pass


class DryRunSession:
    """Drop-in replacement for requests.Session that prints instead of sending.

    Compatible with ``requests.Session`` interface used by spring2shell.
    """

    def request(
        self,
        method: str,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        headers: dict | None = None,
        params: dict | None = None,
        timeout: Any = None,
        **kwargs: Any,
    ) -> _FakeResponse:
        body = data or json
        body_str = str(body)[:200] if body else "(none)"
        headers_str = ", ".join(
            f"{k}: {v}" for k, v in (headers or {}).items()
            if k.lower() not in ("authorization",)  # redact auth
        )
        # Full URL with query params
        if params:
            qs = urllib.parse.urlencode(params)
            display_url = f"{url}?{qs}"
        else:
            display_url = url

        print(f"[DRY-RUN] {method.upper()} {display_url}")
        if headers_str:
            print(f"[DRY-RUN] Headers: {headers_str[:200]}")
        if body_str != "(none)":
            print(f"[DRY-RUN] Body (first 200 chars): {body_str}")

        resp = _FakeResponse()
        resp.url = display_url
        return resp

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self.request("OPTIONS", url, **kwargs)

    # Minimal session compatibility
    verify: bool = True
    max_redirects: int = 10
    headers: dict = {}

    def mount(self, *args: Any, **kwargs: Any) -> None:
        pass
