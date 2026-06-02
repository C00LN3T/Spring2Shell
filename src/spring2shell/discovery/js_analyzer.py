"""
JavaScript endpoint extraction via HTML parsing for spring2shell.
"""

from __future__ import annotations

import re
import urllib.parse

import requests

from spring2shell.utils.logging import log_swallowed_exception
from spring2shell.utils.network import ssl_verify


def analyze_js_endpoints(target_url: str) -> list[str]:
    """Extract API endpoint hints from inline and external JavaScript.

    Fetches the target page, finds ``<script src=...>`` tags (up to 8),
    fetches those scripts, and looks for ``fetch(...)`` calls in both
    the page HTML and the script content.

    Args:
        target_url: Base URL to analyse.

    Returns:
        Deduplicated list of URL paths referenced in JS fetch() calls.
    """
    endpoints: list[str] = []
    try:
        resp = requests.get(target_url, timeout=4, verify=ssl_verify())
        if resp.status_code == 200:
            script_paths = re.findall(r'<script[^>]+src="([^"]+)"', resp.text)
            for path in script_paths[:8]:
                try:
                    js_resp = requests.get(
                        urllib.parse.urljoin(target_url, path),
                        timeout=4,
                        verify=ssl_verify(),
                    )
                    matches = re.findall(r"fetch\(['\"]([^'\"]+)", js_resp.text)
                    endpoints.extend(matches)
                except Exception:
                    continue
            inline_calls = re.findall(r"fetch\(['\"]([^'\"]+)", resp.text)
            endpoints.extend(inline_calls)
    except Exception as exc:
        log_swallowed_exception("analyze_js_endpoints", exc)

    return list(
        {
            urllib.parse.urlparse(e).path
            for e in endpoints
            if e.startswith(("/", "http"))
        }
    )
