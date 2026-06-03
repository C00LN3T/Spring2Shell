"""
SSTI (Server-Side Template Injection) scanner for spring2shell.

Detects template injection via arithmetic probe (7*7 → 49) across
SpEL, FreeMarker, Thymeleaf, Velocity, Groovy, OGNL, Pebble, Jinja2.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any

from spring2shell.core.reporter import build_finding
from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.auth import apply_auth, audit_log, rate_limit_acquire
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.signals import is_interrupted

# ---------------------------------------------------------------------------
# Payload loader
# ---------------------------------------------------------------------------


def _load_ssti_payloads() -> dict[str, Any]:
    path = Path(__file__).parents[3] / "data" / "payloads" / "ssti_payloads.json"
    try:
        with path.open() as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return {}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# The probe result we look for: 7*7 = 49
_PROBE_RESULT = "49"

# Content types to try for POST injection
_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
]

# Common field names to inject probes into
_INJECT_FIELDS = ["query", "search", "input", "name", "value", "template", "message", "body"]


def _check_ssti_response(resp_text: str) -> bool:
    """Return True if the arithmetic probe result '49' appears in the response."""
    return _PROBE_RESULT in resp_text


# ---------------------------------------------------------------------------
# Main SSTI scan
# ---------------------------------------------------------------------------


def ssti_scan(target_url: str, endpoints: list[str] | None = None) -> list[dict[str, Any]]:
    """Probe *target_url* for Server-Side Template Injection.

    Uses arithmetic probes (7*7 → 49) for each template engine to detect injection.
    Avoids sending RCE payloads during the detection phase.

    Args:
        target_url: Base URL of the target.
        endpoints:  Endpoint paths to test (default: common API + GraphQL paths).

    Returns:
        List of finding dicts.
    """
    log_event(logging.INFO, "ssti-scan start", target=target_url)
    findings: list[dict[str, Any]] = []

    ssti_db = _load_ssti_payloads()
    if not ssti_db:
        log_event(logging.WARNING, "SSTI payloads database empty or unreadable")
        return findings

    session = create_stealth_session()
    apply_auth(session)

    if not endpoints:
        endpoints = [
            "/graphql",
            "/api/graphql",
            "/api/v1/graphql",
            "/api/search",
            "/api/query",
            "/api/v1/query",
            "/search",
            "/query",
            "/template",
            "/render",
        ]

    engines = {
        name: data
        for name, data in ssti_db.items()
        if isinstance(data, dict) and "probe" in data and not name.startswith("_")
    }

    for ep in endpoints:
        if is_interrupted():
            break
        full_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/"))

        for engine_name, engine_data in engines.items():
            if is_interrupted():
                break

            probe = engine_data["probe"]
            headers = get_random_headers()

            # ── POST injection (JSON body) ─────────────────────────────────
            for field in _INJECT_FIELDS[:4]:
                rate_limit_acquire()
                post_body = json.dumps({field: probe})
                headers["Content-Type"] = "application/json"
                try:
                    resp = session.post(full_url, data=post_body, headers=headers, timeout=8)
                    audit_log("POST", full_url, resp.status_code, post_body, "ssti_probe")
                    if _check_ssti_response(resp.text):
                        findings.append(
                            build_finding(
                                url=target_url,
                                endpoint=full_url,
                                status="unverified",
                                confidence="high",
                                reason=f"SSTI_{engine_name.upper()}_PROBE",
                                evidence=(
                                    f"Template engine '{engine_name}' probe reflected result "
                                    f"'{_PROBE_RESULT}' (7*7=49) via POST {field}={probe!r}"
                                ),
                                payload=post_body[:200],
                                method="POST",
                                status_code=resp.status_code,
                                framework=engine_name,
                            )
                        )
                        log_event(
                            logging.WARNING,
                            f"SSTI candidate [{engine_name}]",
                            url=full_url,
                            field=field,
                        )
                        # One confirmed engine per endpoint is enough
                        break
                except Exception as exc:
                    log_swallowed_exception(f"ssti-scan {engine_name} POST {full_url}", exc)

            # ── GET parameter injection ────────────────────────────────────
            rate_limit_acquire()
            probe_url = f"{full_url}?query={urllib.parse.quote(probe)}"
            try:
                resp = session.get(probe_url, headers=headers, timeout=8)
                audit_log("GET", probe_url, resp.status_code, probe, "ssti_probe")
                if _check_ssti_response(resp.text):
                    findings.append(
                        build_finding(
                            url=target_url,
                            endpoint=full_url,
                            status="unverified",
                            confidence="high",
                            reason=f"SSTI_{engine_name.upper()}_PROBE_GET",
                            evidence=(
                                f"Template engine '{engine_name}' probe reflected result "
                                f"'{_PROBE_RESULT}' via GET ?query={probe!r}"
                            ),
                            payload=f"?query={probe}",
                            method="GET",
                            status_code=resp.status_code,
                            framework=engine_name,
                        )
                    )
                    log_event(
                        logging.WARNING, f"SSTI candidate [{engine_name}] via GET", url=full_url
                    )
            except Exception as exc:
                log_swallowed_exception(f"ssti-scan {engine_name} GET {full_url}", exc)

            time.sleep(0.2)

    log_event(logging.INFO, "ssti-scan complete", findings=len(findings))
    return findings
