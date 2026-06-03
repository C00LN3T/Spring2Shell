"""
Technology fingerprinting, tech→CVE mapping, and subdomain enumeration for spring2shell.
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

# Markers searched in response body and headers
_TECH_MARKERS = [
    # JavaScript frameworks
    "next.js",
    "react",
    "angular",
    "vue",
    # Backend / Java
    "spring",
    "spring-boot",
    "spring-boot-3",
    "actuator",
    "webflux",
    # API layers
    "graphql",
    "apollo",
    "grpc",
    # Java app servers
    "apache tomcat",
    "undertow",
    "jetty",
    # Middleware
    "activemq",
    # Log4j indicators in headers/pages
    "log4j",
    # Apache commons
    "commons-text",
    # Hosting
    "vercel",
    "express",
    # Other
    "php-cgi",
    "struts",
    "jenkins",
    "elasticsearch",
]

# Additional header-based markers: header name → tech tag
_HEADER_MARKERS: dict[str, str] = {
    "x-powered-by": None,  # inspect value
    "x-nextjs-page": "next.js",
    "x-amz-cf-id": "cloudfront",
    "server": None,  # inspect value (Tomcat, Jetty, etc.)
    "x-application-context": "spring-boot",
}

# Fine-grained header value patterns
_HEADER_VALUE_PATTERNS: list[tuple[str, str]] = [
    ("x-powered-by", "next.js"),
    ("x-powered-by", "express"),
    ("x-powered-by", "php"),
    ("server", "tomcat"),
    ("server", "jetty"),
    ("server", "undertow"),
    ("server", "apache"),
    ("server", "nginx"),
    ("server", "iis"),
]

# ─── Tech → CVE priority map ──────────────────────────────────────────────────
TECH_CVE_MAP: dict[str, list[str]] = {
    "spring": ["CVE-2025-55182", "CVE-2022-22965", "CVE-2024-22243"],
    "spring-boot": ["CVE-2025-55182", "CVE-2022-22965", "CVE-2024-22243"],
    "spring-boot-3": ["CVE-2025-55182", "CVE-2024-38816", "CVE-2024-22243"],
    "actuator": ["CVE-2025-55182", "CVE-2022-22965"],
    "webflux": ["CVE-2024-38816", "CVE-2025-55182"],
    "graphql": ["CVE-2025-55182", "CVE-2025-66478"],
    "apollo": ["CVE-2025-55182", "CVE-2025-66478"],
    "next.js": ["CVE-2025-55182", "CVE-2025-66478"],
    "react": ["CVE-2025-55182", "CVE-2025-66478"],
    "angular": ["CVE-2025-55182"],
    "vue": ["CVE-2025-55182"],
    "activemq": ["CVE-2023-46604"],
    "log4j": ["CVE-2021-44228"],
    "commons-text": ["CVE-2022-42889"],
    "struts": ["CVE-2022-42889"],  # OGNL via Text4Shell
    "php-cgi": ["CVE-2024-4577"],
    "jenkins": ["CVE-2021-44228"],  # Log4j
    "elasticsearch": ["CVE-2021-44228"],  # Log4j
    "express": ["CVE-2025-55182"],
    "vercel": ["CVE-2025-55182", "CVE-2025-66478"],
}

# Ordered priority: CVEs in this list appear first when sorting
_CVE_PRIORITY = [
    "CVE-2025-55182",
    "CVE-2025-66478",
    "CVE-2022-22965",
    "CVE-2021-44228",
    "CVE-2022-42889",
    "CVE-2023-46604",
    "CVE-2024-22243",
    "CVE-2024-38816",
    "CVE-2024-4577",
    "CVE-2023-34104",
    "CVE-2024-21626",
]


def get_cves_for_fingerprints(fingerprints: list[str]) -> list[str]:
    """Return deduplicated, priority-sorted CVE IDs for the detected tech stack.

    Args:
        fingerprints: List of tech markers returned by :func:`tech_fingerprint`.

    Returns:
        Deduplicated list of CVE IDs, ordered by :data:`_CVE_PRIORITY`.
        Falls back to **all** known CVEs when *fingerprints* is empty.
    """
    if not fingerprints:
        # No fingerprints — test everything
        all_cves: list[str] = []
        for cves in TECH_CVE_MAP.values():
            all_cves.extend(cves)
        return _deduplicate_sorted(all_cves)

    relevant: list[str] = []
    for fp in fingerprints:
        relevant.extend(TECH_CVE_MAP.get(fp, []))

    if not relevant:
        # Fingerprints found but not in our map — fall back to all CVEs
        log_event(logging.DEBUG, f"No CVE mapping for fingerprints {fingerprints} — using all CVEs")
        return get_cves_for_fingerprints([])

    return _deduplicate_sorted(relevant)


def _deduplicate_sorted(cves: list[str]) -> list[str]:
    """Deduplicate CVE list and sort by priority order."""
    seen: set[str] = set()
    result: list[str] = []
    # First: emit priority-ordered CVEs
    for cve in _CVE_PRIORITY:
        if cve in cves and cve not in seen:
            result.append(cve)
            seen.add(cve)
    # Then: any remaining CVEs not in priority list
    for cve in cves:
        if cve not in seen:
            result.append(cve)
            seen.add(cve)
    return result


def prioritize_endpoints(endpoints: list[str], fingerprints: list[str]) -> list[str]:
    """Re-order *endpoints* to test the most relevant ones first.

    Args:
        endpoints:    Full list of discovered endpoints.
        fingerprints: Detected tech markers.

    Returns:
        Reordered list (highest priority first), deduplicated.
    """
    priority_prefixes: list[str] = []
    if any(fp in ("graphql", "apollo", "next.js", "react") for fp in fingerprints):
        priority_prefixes += ["/graphql", "/api/graphql", "/v1/graphql", "/__graphql"]
    if any(fp in ("spring", "spring-boot", "actuator") for fp in fingerprints):
        priority_prefixes += [
            "/actuator",
            "/actuator/env",
            "/actuator/beans",
            "/api/",
            "/api/v1/",
            "/api/v2/",
        ]
    if "activemq" in fingerprints:
        priority_prefixes += ["/admin/", "/api/jolokia/", "/hawtio/", "/console/"]
    if "webflux" in fingerprints:
        priority_prefixes += ["/static/", "/resources/", "/webjars/"]

    seen: set[str] = set()
    ordered: list[str] = []
    for prefix in priority_prefixes:
        for ep in endpoints:
            if ep.startswith(prefix) and ep not in seen:
                ordered.append(ep)
                seen.add(ep)
    for ep in endpoints:
        if ep not in seen:
            ordered.append(ep)
            seen.add(ep)
    return ordered


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
        fingerprints: list[str] = []

        # Body / header marker scan
        for marker in _TECH_MARKERS:
            if marker in text or any(marker in v for v in hdrs.values()):
                fingerprints.append(marker)

        # Header value patterns
        for hdr_name, pattern in _HEADER_VALUE_PATTERNS:
            if hdr_name in hdrs and pattern in hdrs[hdr_name]:
                if pattern not in fingerprints:
                    fingerprints.append(pattern)

        # Spring Boot version detection
        if "spring-boot" in fingerprints:
            # Detect v3 from X-Application-Context or body version strings
            if (
                "spring-boot: 3" in text
                or "spring.boot.version=3" in text
                or "org.springframework.boot:spring-boot:3" in text
            ):
                fingerprints.append("spring-boot-3")

        fingerprints = list(dict.fromkeys(fingerprints))  # deduplicate preserving order

        if fingerprints:
            log_event(
                logging.INFO,
                "Tech fingerprint",
                target=target_url,
                markers=",".join(fingerprints),
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
                resp = requests.head(variant, timeout=2, verify=ssl_verify(), allow_redirects=True)
                if resp.status_code < 500:
                    discovered.append(variant)
            except Exception as exc:
                log_swallowed_exception(f"subdomain probe {variant}", exc)

    unique = list(set(discovered))
    _SUBDOMAIN_CACHE[target_url] = unique
    return unique
