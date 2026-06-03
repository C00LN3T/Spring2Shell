"""
Asynchronous network utilities for spring2shell.
Provides aiohttp session creation and retry-enabled request wrappers.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from spring2shell.utils.auth import async_rate_limit_acquire, get_auth_config, get_proxy_url
from spring2shell.utils.network import RETRY_PROFILES, TIMEOUT_PROFILES, ssl_verify


def create_async_session(profile: str = "default") -> aiohttp.ClientSession:
    """Create an aiohttp ClientSession configured for the reliability profile.

    Args:
        profile: The configuration profile.

    Returns:
        Configured aiohttp.ClientSession instance.
    """
    auth = get_auth_config()
    headers = {}

    # User-agent or other headers
    if auth.bearer:
        headers["Authorization"] = f"Bearer {auth.bearer}"
    if auth.headers:
        headers.update(auth.headers)

    auth_obj = None
    if auth.basic:
        auth_obj = aiohttp.BasicAuth(auth.basic[0], auth.basic[1])

    timeout_val = TIMEOUT_PROFILES.get(profile, TIMEOUT_PROFILES.get("default", 6.0))
    timeout = aiohttp.ClientTimeout(total=timeout_val)

    # SSL configuration
    verify = ssl_verify()
    connector = aiohttp.TCPConnector(ssl=None if verify else False)

    session = aiohttp.ClientSession(
        connector=connector,
        headers=headers,
        cookies=auth.cookies,
        auth=auth_obj,
        timeout=timeout,
        trust_env=True,
    )

    # Store proxy settings on the session for request-level application
    proxy_url = get_proxy_url()
    if proxy_url:
        session.proxy_url = proxy_url

    return session


async def send_async_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    profile: str = "default",
    **kwargs: Any,
) -> aiohttp.ClientResponse:
    """Send an async request using aiohttp with backoff-based retries.

    Args:
        session: The active ClientSession.
        method:  HTTP method (GET, POST, etc.)
        url:     Target endpoint URL.
        profile: Configuration profile name for retries.
        kwargs:  Pass-through arguments to session.request.

    Returns:
        The aiohttp ClientResponse object.
    """
    cfg = RETRY_PROFILES.get(profile, RETRY_PROFILES["default"])
    total_retries = cfg.get("total", 3)
    backoff = cfg.get("backoff_factor", 0.4)

    # Apply proxy if configured
    proxy = getattr(session, "proxy_url", None)
    if proxy and "proxy" not in kwargs:
        kwargs["proxy"] = proxy

    # aiohttp ClientSession requires allow_redirects instead of allow_redirects=False for some methods
    # or handle standard requests redirects parameter
    if "allow_redirects" not in kwargs:
        kwargs["allow_redirects"] = False

    for attempt in range(total_retries + 1):
        try:
            await async_rate_limit_acquire()

            resp = await session.request(method, url, **kwargs)

            # Retry on transient server errors or rate limiting
            if resp.status in [429, 500, 502, 503, 504] and attempt < total_retries:
                # Need to release connection before retrying or read content
                await resp.release()
                await asyncio.sleep(backoff * (2**attempt))
                continue
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if attempt < total_retries:
                await asyncio.sleep(backoff * (2**attempt))
                continue
            raise exc

    raise aiohttp.ClientError("Max retries exceeded")
