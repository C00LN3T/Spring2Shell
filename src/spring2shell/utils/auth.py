"""
Authentication and proxy configuration for spring2shell.

Provides:
- AuthConfig:    dataclass holding parsed auth credentials
- configure_auth():  populate AuthConfig from CLI args
- apply_auth():      apply auth to a requests.Session
- RateLimiter:   thread-safe token-bucket rate limiter
- AuditLogger:   append-only JSONL audit trail
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from spring2shell.utils.logging import log_event

# ---------------------------------------------------------------------------
# Auth config
# ---------------------------------------------------------------------------


@dataclass
class AuthConfig:
    """Holds all authentication credentials for the current session."""

    bearer: str | None = None
    basic: tuple[str, str] | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_configured(self) -> bool:
        return any([self.bearer, self.basic, self.cookies, self.headers])


# Module-level singleton
_auth_config = AuthConfig()
_proxy_url: str | None = None
_webhook_url: str | None = None


def get_auth_config() -> AuthConfig:
    return _auth_config


def get_proxy_url() -> str | None:
    return _proxy_url


def get_webhook_url() -> str | None:
    return _webhook_url


def configure_auth(args: Any) -> None:
    """Populate global AuthConfig from parsed CLI args."""
    global _auth_config

    bearer = getattr(args, "auth_bearer", None)
    basic_raw = getattr(args, "auth_basic", None)
    cookie_raw = getattr(args, "auth_cookie", None)
    header_raw = getattr(args, "auth_header", None)

    basic = None
    if basic_raw:
        parts = basic_raw.split(":", 1)
        if len(parts) == 2:
            basic = (parts[0], parts[1])
        else:
            log_event(logging.WARNING, f"--auth-basic format must be USER:PASS, got: {basic_raw!r}")

    cookies: dict[str, str] = {}
    if cookie_raw:
        for pair in cookie_raw.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers: dict[str, str] = {}
    if header_raw:
        for pair in header_raw.split(";"):
            pair = pair.strip()
            if ":" in pair:
                k, v = pair.split(":", 1)
                headers[k.strip()] = v.strip()

    _auth_config = AuthConfig(bearer=bearer, basic=basic, cookies=cookies, headers=headers)
    if _auth_config.is_configured:
        methods = []
        if bearer:
            methods.append("Bearer")
        if basic:
            methods.append("Basic")
        if cookies:
            methods.append(f"Cookie({len(cookies)})")
        if headers:
            methods.append(f"Header({len(headers)})")
        log_event(logging.INFO, f"Auth configured: {', '.join(methods)}")


def configure_proxy(args: Any) -> None:
    """Set global proxy URL from CLI args."""
    global _proxy_url
    proxy = getattr(args, "proxy", None)
    if proxy:
        _proxy_url = proxy
        log_event(logging.INFO, f"Proxy configured: {proxy}")


def configure_webhook(args: Any) -> None:
    """Set global webhook URL from CLI args."""
    global _webhook_url
    url = getattr(args, "webhook", None)
    if url:
        _webhook_url = url
        log_event(logging.INFO, f"Webhook configured: {url}")


def apply_auth(session: requests.Session) -> None:
    """Apply auth credentials and proxy to an existing session."""
    auth = _auth_config
    if auth.bearer:
        session.headers.update({"Authorization": f"Bearer {auth.bearer}"})
    if auth.basic:
        session.auth = auth.basic
    if auth.cookies:
        session.cookies.update(auth.cookies)
    if auth.headers:
        session.headers.update(auth.headers)

    if _proxy_url:
        session.proxies = {"http": _proxy_url, "https": _proxy_url}
        log_event(logging.DEBUG, f"Proxy applied: {_proxy_url}")


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe token-bucket rate limiter.

    Args:
        rps: Maximum requests per second. 0 means unlimited.
    """

    def __init__(self, rps: int) -> None:
        self.rps = max(0, rps)
        if self.rps > 0:
            self._lock = threading.Lock()
            self._tokens = float(rps)
            self._last = time.monotonic()

    def acquire(self) -> None:
        """Block until a request token is available."""
        if self.rps <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.rps, self._tokens + elapsed * self.rps)
            if self._tokens >= 1:
                self._tokens -= 1
                return
            wait = (1.0 - self._tokens) / self.rps
        time.sleep(wait)
        with self._lock:
            self._tokens = max(0.0, self._tokens - 1)

    async def async_acquire(self) -> None:
        """Asynchronously acquire a token without blocking the event loop."""
        import asyncio

        if self.rps <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.rps, self._tokens + elapsed * self.rps)
            if self._tokens >= 1:
                self._tokens -= 1
                return
            wait = (1.0 - self._tokens) / self.rps
        await asyncio.sleep(wait)
        with self._lock:
            self._tokens = max(0.0, self._tokens - 1)


# Module-level rate limiter (None = unlimited)
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter | None:
    return _rate_limiter


def configure_rate(args: Any) -> None:
    """Initialise global rate limiter from CLI args."""
    global _rate_limiter
    rate = getattr(args, "rate", 0) or 0
    if rate > 0:
        _rate_limiter = RateLimiter(rate)
        log_event(logging.INFO, f"Rate limiter active: {rate} req/s")


def rate_limit_acquire() -> None:
    """Acquire a rate-limit token if a limiter is configured."""
    if _rate_limiter:
        _rate_limiter.acquire()


async def async_rate_limit_acquire() -> None:
    """Asynchronously acquire a rate-limit token if a limiter is configured."""
    if _rate_limiter:
        await _rate_limiter.async_acquire()


# ---------------------------------------------------------------------------
# Audit logger (JSONL)
# ---------------------------------------------------------------------------


class AuditLogger:
    """Append-only JSONL audit trail for every HTTP request.

    Each line is a JSON object with fields:
        ts, method, url, status, ph (payload hash), result
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        log_event(logging.INFO, f"AuditLogger initialised: {self.path}")

    def log_request(
        self,
        method: str,
        url: str,
        status: int | None,
        payload: str | None = None,
        result: str = "",
    ) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "ph": hashlib.sha256((payload or "").encode()).hexdigest()[:12],
            "result": result,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# Module-level audit logger (None = disabled)
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger | None:
    return _audit_logger


def configure_audit(args: Any) -> None:
    """Initialise global audit logger from CLI args."""
    global _audit_logger
    path = getattr(args, "audit_log", None)
    if path:
        _audit_logger = AuditLogger(path)


def audit_log(
    method: str, url: str, status: int | None, payload: str | None = None, result: str = ""
) -> None:
    """Write one entry to the audit log if enabled."""
    if _audit_logger:
        _audit_logger.log_request(method, url, status, payload, result)


# ---------------------------------------------------------------------------
# Webhook notifications
# ---------------------------------------------------------------------------


def send_webhook(finding: dict[str, Any]) -> None:
    """POST a JSON notification to the configured webhook URL.

    Fires for every confirmed finding. Non-blocking on failure.
    """
    url = _webhook_url
    if not url:
        return
    from spring2shell.utils.network import ssl_verify

    payload = {
        "text": f"🚨 Confirmed RCE: {finding.get('url', 'N/A')}",
        "severity": "critical",
        "endpoint": finding.get("endpoint", "N/A"),
        "evidence": finding.get("evidence", ""),
        "cve": finding.get("cve", "Unknown"),
        "timestamp": finding.get("timestamp", datetime.now(timezone.utc).isoformat()),
    }
    try:
        resp = requests.post(url, json=payload, timeout=5, verify=ssl_verify())
        log_event(logging.DEBUG, f"Webhook sent: HTTP {resp.status_code}")
    except Exception as exc:
        log_event(logging.WARNING, f"Webhook failed: {exc}")
