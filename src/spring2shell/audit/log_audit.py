"""
Passive Log4Shell / Log2Shell risk audit for spring2shell.

Provides:
- run_log_audit():       structured findings for CI/JSON reporting
- safe_log_audit():      rich findings dict with version parsing and risk level
- _parse_log4j_versions(): extract Log4j version strings from response text
- _is_log4j_vulnerable():  check if a version falls in CVE-2021-44228 range
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any

import requests

from spring2shell.core.reporter import build_finding
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify

_LOG4J_PATHS = [
    "/actuator/loggers",
    "/actuator/loggers/",
    "/actuator/logfile",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/info",
    "/v2/api-docs",
    "/v3/api-docs",
]

_LOG4J_VERSION_PATTERNS = [
    "log4j-core",
    "log4j2",
    "log4j-",
    "2.14.1",
    "2.15.0",
]

# Regex patterns for exact version extraction
_LOG4J_REGEX_PATTERNS = [
    r"log4j(?:-core|-api)?[^0-9]{0,8}(2\.\d+\.\d+)",
    r"org\.apache\.logging\.log4j[^0-9]{0,20}(2\.\d+\.\d+)",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_log4j_versions(text: str) -> list[str]:
    """Extract Log4j version strings from response text.

    Args:
        text: Response body text to search.

    Returns:
        Sorted list of distinct version strings found (e.g. ``["2.14.1", "2.16.0"]``).
    """
    versions: set[str] = set()
    for pattern in _LOG4J_REGEX_PATTERNS:
        for m in re.findall(pattern, text, flags=re.IGNORECASE):
            versions.add(m)
    return sorted(versions)


def _is_log4j_vulnerable(version: str) -> bool:
    """Return True if *version* falls in the Log4Shell vulnerable range.

    Vulnerable: Log4j 2.0.0 – 2.14.1 (CVE-2021-44228).
    Also flags 2.15.0 as potentially vulnerable (incomplete fix).

    Args:
        version: Dot-separated version string such as ``"2.14.1"``.

    Returns:
        True if the version is in a known-vulnerable range.
    """
    try:
        parts = tuple(int(x) for x in version.split("."))
    except Exception:
        return False
    return (2, 0, 0) <= parts <= (2, 15, 0)


# ---------------------------------------------------------------------------
# Structured findings (for reporter/CI)
# ---------------------------------------------------------------------------


def run_log_audit(target_url: str) -> list[dict[str, Any]]:
    """Passive Log4Shell risk assessment returning structured finding dicts.

    Probes management endpoints for Log4j version strings and
    exposed logger configuration without sending JNDI payloads.

    Args:
        target_url: Base URL to audit.

    Returns:
        List of finding dicts from :func:`~core.reporter.build_finding`.
    """
    log_event(logging.INFO, "log-audit start", target=target_url)
    findings: list[dict[str, Any]] = []

    for path in _LOG4J_PATHS:
        url = urllib.parse.urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = requests.get(url, timeout=5, verify=ssl_verify(), allow_redirects=False)
            if resp.status_code in (200, 206):
                body = resp.text.lower()
                for pattern in _LOG4J_VERSION_PATTERNS:
                    if pattern in body:
                        findings.append(
                            build_finding(
                                url=target_url,
                                endpoint=url,
                                status="unverified",
                                confidence="medium",
                                cve="CVE-2021-44228",
                                reason="LOG4J_VERSION_INDICATOR",
                                evidence=f"Pattern {pattern!r} found in {path} response",
                                method="GET",
                                status_code=resp.status_code,
                            )
                        )
                        break

                # Exact version extraction
                versions = _parse_log4j_versions(resp.text)
                for v in versions:
                    if _is_log4j_vulnerable(v):
                        findings.append(
                            build_finding(
                                url=target_url,
                                endpoint=url,
                                status="confirmed",
                                confidence="high",
                                cve="CVE-2021-44228",
                                reason="LOG4J_VULNERABLE_VERSION_DETECTED",
                                evidence=f"Potentially vulnerable Log4j version detected: {v}",
                                method="GET",
                                status_code=resp.status_code,
                            )
                        )

                if resp.status_code == 200 and "loggers" in path:
                    findings.append(
                        build_finding(
                            url=target_url,
                            endpoint=url,
                            status="unverified",
                            confidence="low",
                            reason="EXPOSED_LOGGER_ENDPOINT",
                            evidence=f"Actuator logger endpoint accessible at {path}",
                            method="GET",
                            status_code=resp.status_code,
                        )
                    )
        except Exception as exc:
            log_swallowed_exception(f"log-audit {path}", exc)

    log_event(logging.INFO, "log-audit complete", findings=len(findings))
    return findings


# ---------------------------------------------------------------------------
# Rich audit dict (for safe_full_audit / JSON report)
# ---------------------------------------------------------------------------


def safe_log_audit(target_url: str) -> dict[str, Any]:
    """Rich passive Log4Shell audit returning a full findings dict.

    Returns:
        Dict with ``target``, ``checked_paths``, ``versions_detected``,
        ``risk`` (low/medium/high), ``evidence`` list.
    """
    log_event(logging.INFO, "safe_log_audit start", target=target_url)
    base = target_url.rstrip("/")
    audit_findings: dict[str, Any] = {
        "target": target_url,
        "checked_paths": [],
        "versions_detected": [],
        "risk": "low",
        "evidence": [],
    }

    for path in _LOG4J_PATHS:
        url = urllib.parse.urljoin(base + "/", path.lstrip("/"))
        try:
            resp = requests.get(url, timeout=8, verify=ssl_verify())
        except Exception as exc:
            log_swallowed_exception(f"safe_log_audit {path}", exc)
            continue

        audit_findings["checked_paths"].append(
            {
                "path": path,
                "status_code": resp.status_code,
            }
        )
        text = resp.text[:200_000]
        lower = text.lower()

        if resp.status_code == 200 and path.startswith("/actuator"):
            audit_findings["evidence"].append(f"Accessible management endpoint: {path}")
        if "log4j" in lower or "log4shell" in lower or "jndilookup" in lower:
            audit_findings["evidence"].append(f"Log-related indicator on {path}")
        versions = _parse_log4j_versions(text)
        for v in versions:
            if v not in audit_findings["versions_detected"]:
                audit_findings["versions_detected"].append(v)

    vulnerable_versions = [
        v for v in audit_findings["versions_detected"] if _is_log4j_vulnerable(v)
    ]
    if vulnerable_versions:
        audit_findings["risk"] = "high"
        audit_findings["evidence"].append(
            f"Potentially vulnerable Log4j versions: {', '.join(vulnerable_versions)}"
        )
    elif audit_findings["evidence"]:
        audit_findings["risk"] = "medium"

    log_event(
        logging.INFO,
        "safe_log_audit complete",
        risk=audit_findings["risk"],
        versions=audit_findings["versions_detected"],
    )
    return audit_findings
