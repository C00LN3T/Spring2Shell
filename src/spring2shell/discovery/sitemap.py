"""
Sitemap.xml parser for endpoint discovery in spring2shell.
"""

from __future__ import annotations

import re
import urllib.parse

import requests

from spring2shell.utils.logging import log_swallowed_exception
from spring2shell.utils.network import ssl_verify


def parse_sitemap(target_url: str) -> list[str]:
    """Fetch and parse ``/sitemap.xml`` to extract URL hints.

    Args:
        target_url: Base URL. ``/sitemap.xml`` is appended automatically.

    Returns:
        List of URLs extracted from ``<loc>`` elements, or an empty list
        if the sitemap is absent or invalid.
    """
    urls: list[str] = []
    try:
        resp = requests.get(
            urllib.parse.urljoin(target_url, "/sitemap.xml"),
            timeout=4,
            verify=ssl_verify(),
        )
        if resp.status_code == 200 and "<urlset" in resp.text:
            for loc in re.findall(r"<loc>([^<]+)</loc>", resp.text):
                urls.append(loc.strip())
    except Exception as exc:
        log_swallowed_exception("parse_sitemap", exc)
    return urls
