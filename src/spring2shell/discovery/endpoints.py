"""
Endpoint discovery and prioritisation for spring2shell.

Provides:
- load_endpoints():      load ENDPOINTS list from data/endpoints/endpoints.txt
- load_cve_endpoints():  load CVE_ENDPOINTS from data/endpoints/cve_endpoints.txt
- discover_endpoints():  combined discovery (static + sitemap + JS analysis)
- prioritize_endpoints(): score and sort endpoints based on tech fingerprints
"""

from __future__ import annotations

import logging
import urllib.parse
from pathlib import Path

from spring2shell.utils.logging import log_event
from spring2shell.utils.signals import is_interrupted

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------
_ENDPOINT_DISCOVERY_CACHE: dict[str, list[str]] = {}

# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def _load_list(path: Path) -> list[str]:
    """Read a flat text file (one path per line, # comments ignored)."""
    try:
        return [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except FileNotFoundError:
        return []


def load_endpoints(data_root: str | Path | None = None) -> list[str]:
    """Load the unified ENDPOINTS wordlist from data/endpoints/endpoints.txt."""
    if data_root is None:
        data_root = Path(__file__).parents[3] / "data"
    return _load_list(Path(data_root) / "endpoints" / "endpoints.txt")


def load_cve_endpoints(data_root: str | Path | None = None) -> list[str]:
    """Load the CVE-focused ENDPOINTS list from data/endpoints/cve_endpoints.txt."""
    if data_root is None:
        data_root = Path(__file__).parents[3] / "data"
    return _load_list(Path(data_root) / "endpoints" / "cve_endpoints.txt")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_endpoints(target_url: str) -> list[str]:
    """Combine static wordlists with dynamic sitemap + JS discovery.

    Results are cached per target URL to avoid redundant network calls.

    Args:
        target_url: Base URL of the target.

    Returns:
        Deduplicated list of endpoint paths.
    """
    if target_url in _ENDPOINT_DISCOVERY_CACHE:
        return _ENDPOINT_DISCOVERY_CACHE[target_url]

    from spring2shell.discovery.sitemap import parse_sitemap
    from spring2shell.discovery.js_analyzer import analyze_js_endpoints

    endpoints: set[str] = set(load_endpoints()) | set(load_cve_endpoints())

    if not is_interrupted():
        for url in parse_sitemap(target_url):
            endpoints.add(urllib.parse.urlparse(url).path)

    if not is_interrupted():
        for js_path in analyze_js_endpoints(target_url):
            endpoints.add(js_path)

    resolved = list(endpoints)
    _ENDPOINT_DISCOVERY_CACHE[target_url] = resolved
    return resolved


# ---------------------------------------------------------------------------
# Prioritisation
# ---------------------------------------------------------------------------

_ENDPOINT_WEIGHTS: dict[str, int] = {
    "graphql": 8,
    "api": 6,
    "actuator": 5,
    "swagger": 4,
    "graphiql": 3,
    "openapi": 3,
}

_TECH_BONUS: dict[str, dict[str, int]] = {
    "next.js": {"/": 10},
    "react": {"/": 8},
    "spring": {"actuator": 7, "graphql": 5},
    "graphql": {"graphql": 9},
}


def prioritize_endpoints(endpoints: list[str], fingerprints: list[str]) -> list[str]:
    """Sort *endpoints* by relevance score given observed tech *fingerprints*.

    Args:
        endpoints:    List of URL paths.
        fingerprints: Tech markers detected via :func:`~discovery.fingerprint.tech_fingerprint`.

    Returns:
        Sorted list, highest-priority first.
    """
    def score(endpoint: str) -> int:
        base = 1
        ep_lower = endpoint.lower()
        for key, value in _ENDPOINT_WEIGHTS.items():
            if key in ep_lower:
                base += value
        for marker in fingerprints:
            for hint, bonus in _TECH_BONUS.get(marker, {}).items():
                if hint in ep_lower:
                    base += bonus
        return base

    prioritized = sorted(set(endpoints), key=score, reverse=True)
    if fingerprints:
        log_event(
            logging.DEBUG,
            "Endpoint prioritization",
            markers=",".join(fingerprints),
            top=prioritized[:3],
        )
    return prioritized
