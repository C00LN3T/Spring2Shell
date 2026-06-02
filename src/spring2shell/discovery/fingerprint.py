"""
Technology fingerprinting and subdomain enumeration for spring2shell.
"""

from __future__ import annotations

import logging
import urllib.parse

import requests

from spring2shell.evasion.headers import protocol_hopper
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify

_TECH_FP_CACHE: dict[str, list[str]] = {}
_SUBDOMAIN_CACHE: dict[str, list[str]] = {}

_TECH_MARKERS = ["next.js", "react", "spring", "graphql", "apollo", "vercel", "express"]


def tech_fingerprint(target_url: str) -> list[str]:
    """Detect technology markers from response body and headers.

    Results are cached per URL.

    Args:
        target_url: Base URL to fingerprint.

    Returns:
        List of detected technology marker strings.
    """
    if target_url in _TECH_FP_CACHE:
        return _TECH_FP_CACHE[target_url]
    try:
        resp = requests.get(target_url, timeout=4, verify=ssl_verify())
        text = resp.text.lower()
        hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
        fingerprints = [
            marker
            for marker in _TECH_MARKERS
            if marker in text or any(marker in v for v in hdrs.values())
        ]
        if fingerprints:
            log_event(
                logging.INFO,
                "Tech fingerprint",
                target=target_url,
                markers=",".join(sorted(set(fingerprints))),
            )
        _TECH_FP_CACHE[target_url] = fingerprints
        return fingerprints
    except Exception:
        _TECH_FP_CACHE[target_url] = []
        return []


def enumerate_subdomains(target_url: str) -> list[str]:
    """Probe common subdomain prefixes for the target's hostname.

    Results are cached per URL.

    Args:
        target_url: Base URL whose hostname is used as the parent domain.

    Returns:
        List of responding subdomain URLs (< 500 status code).
    """
    if target_url in _SUBDOMAIN_CACHE:
        return _SUBDOMAIN_CACHE[target_url]

    prefixes = ["api", "dev", "staging", "test", "beta"]
    discovered: list[str] = []
    hostname = urllib.parse.urlparse(target_url).hostname or target_url

    for prefix in prefixes:
        candidate = f"{prefix}.{hostname}"
        for variant in protocol_hopper(candidate):
            try:
                resp = requests.head(
                    variant, timeout=2, verify=ssl_verify(), allow_redirects=True
                )
                if resp.status_code < 500:
                    discovered.append(variant)
            except Exception as exc:
                log_swallowed_exception(f"subdomain probe {variant}", exc)

    unique = list(set(discovered))
    _SUBDOMAIN_CACHE[target_url] = unique
    return unique
