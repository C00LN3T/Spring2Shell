"""
Passive safe-audit modes for spring2shell (no RCE payloads).

Provides:
- safe_encoding_audit():    5-variant marker reflection check (plain/url/double-url/base64/unicode)
- safe_dependency_audit():  detect library version leakage via actuator/swagger
- safe_misconfig_audit():   missing security headers + exposed management endpoints
- safe_full_audit():        combined run → overall_risk assessment
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from typing import Any

from spring2shell.core.session import create_stealth_session
from spring2shell.discovery.endpoints import discover_endpoints, prioritize_endpoints
from spring2shell.discovery.fingerprint import tech_fingerprint
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.signals import is_interrupted

# ---------------------------------------------------------------------------
# Marker variant helpers
# ---------------------------------------------------------------------------


def _marker_variants(marker: str) -> dict[str, str]:
    return {
        "plain": marker,
        "url": urllib.parse.quote(marker, safe=""),
        "double_url": urllib.parse.quote(urllib.parse.quote(marker, safe=""), safe=""),
        "base64": base64.b64encode(marker.encode()).decode(),
        "unicode": "".join(f"\\u{ord(ch):04x}" for ch in marker),
    }


# ---------------------------------------------------------------------------
# safe_encoding_audit
# ---------------------------------------------------------------------------

_AUDIT_PATHS_FAST = [
    "/actuator",
    "/actuator/env",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/api/graphql",
    "/api",
]


def safe_encoding_audit(
    target_url: str,
    endpoints: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Check how the server handles encoded marker values (no exploit payloads).

    Sends 5 marker variants (plain, URL-encoded, double-URL, base64, unicode)
    via both POST and GET.  Records which variants are reflected in responses.

    Args:
        target_url: Base URL.
        endpoints:  Optional list of full URLs to audit. Auto-detected if None.

    Returns:
        List of per-endpoint dicts with ``decoding_observations`` and ``status``.
    """
    log_event(logging.INFO, "safe_encoding_audit start", target=target_url)
    session = create_stealth_session("safe-audit")
    timeout = 8

    if endpoints is None:
        # Quick 20-endpoint probe — no RCE
        candidates = prioritize_endpoints(
            discover_endpoints(target_url), tech_fingerprint(target_url)
        )
        endpoints = [
            urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/"))
            for ep in candidates[:20]
        ]
    endpoints = list(dict.fromkeys(endpoints))

    results: list[dict[str, Any]] = []

    for endpoint in endpoints:
        if is_interrupted():
            break
        import random

        marker = f"SAFE_AUDIT_{random.randint(10000, 99999)}"
        variants = _marker_variants(marker)
        ep_result: dict[str, Any] = {
            "endpoint": endpoint,
            "marker": marker,
            "decoding_observations": [],
            "status": [],
        }

        for variant_name, variant_value in variants.items():
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; spring2shell-safe-audit/2.0)",
                "Content-Type": "application/json",
            }
            body = json.dumps(
                {
                    "audit": "encoding-check",
                    "probe": variant_value,
                    "query": "query Audit { __typename }",
                    "variables": {"probe": variant_value},
                }
            )
            # POST
            try:
                pr = session.post(endpoint, data=body, headers=headers, timeout=timeout)
                ep_result["status"].append(
                    {
                        "method": "POST",
                        "variant": variant_name,
                        "status_code": pr.status_code,
                    }
                )
                if marker in pr.text or variant_value in pr.text:
                    ep_result["decoding_observations"].append(
                        {
                            "method": "POST",
                            "variant": variant_name,
                            "reflected_plain": marker in pr.text,
                            "reflected_encoded": variant_value in pr.text,
                        }
                    )
            except Exception as exc:
                log_swallowed_exception(f"encoding_audit POST {endpoint}", exc)

            # GET
            try:
                gr = session.get(
                    endpoint,
                    params={"probe": variant_value, "audit": "encoding-check"},
                    headers=headers,
                    timeout=timeout,
                )
                ep_result["status"].append(
                    {
                        "method": "GET",
                        "variant": variant_name,
                        "status_code": gr.status_code,
                    }
                )
                if marker in gr.text or variant_value in gr.text:
                    ep_result["decoding_observations"].append(
                        {
                            "method": "GET",
                            "variant": variant_name,
                            "reflected_plain": marker in gr.text,
                            "reflected_encoded": variant_value in gr.text,
                        }
                    )
            except Exception as exc:
                log_swallowed_exception(f"encoding_audit GET {endpoint}", exc)

        if ep_result["decoding_observations"] or ep_result["status"]:
            results.append(ep_result)

    log_event(
        logging.INFO, "safe_encoding_audit complete", endpoints=len(endpoints), results=len(results)
    )
    return results


# ---------------------------------------------------------------------------
# safe_dependency_audit
# ---------------------------------------------------------------------------

_DEPENDENCY_PATHS = [
    "/actuator/env",
    "/actuator/info",
    "/actuator/configprops",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
]

_DEPENDENCY_INDICATORS = [
    "spring-boot",
    "log4j",
    "logback",
    "slf4j",
    "jackson",
    "tomcat",
    "netty",
    "hibernate",
    "reactor",
    "snakeyaml",
    "commons-",
    "org.springframework",
    "fastjson",
    "gson",
    "okhttp",
    "jetty",
    "undertow",
]


def safe_dependency_audit(target_url: str) -> dict[str, Any]:
    """Scan management/swagger endpoints for library version leakage.

    Args:
        target_url: Base URL.

    Returns:
        Dict with ``target``, ``leaks`` (list of path/indicator pairs).
    """
    log_event(logging.INFO, "safe_dependency_audit start", target=target_url)
    session = create_stealth_session("safe-audit")
    results: dict[str, Any] = {"target": target_url, "leaks": []}

    for path in _DEPENDENCY_PATHS:
        url = urllib.parse.urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=8)
            lower = resp.text[:200_000].lower()
            found = [ind for ind in _DEPENDENCY_INDICATORS if ind in lower]
            if found:
                results["leaks"].append(
                    {
                        "path": path,
                        "status_code": resp.status_code,
                        "indicators": found[:20],
                    }
                )
        except Exception as exc:
            log_swallowed_exception(f"dependency_audit {path}", exc)

    log_event(logging.INFO, "safe_dependency_audit complete", leaks=len(results["leaks"]))
    return results


# ---------------------------------------------------------------------------
# safe_misconfig_audit
# ---------------------------------------------------------------------------

_SECURITY_HEADERS_REQUIRED = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
]

_MGMT_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/configprops",
]


def safe_misconfig_audit(target_url: str) -> dict[str, Any]:
    """Check for missing security headers and exposed management endpoints.

    Args:
        target_url: Base URL.

    Returns:
        Dict with ``target``, ``issues`` list.
    """
    log_event(logging.INFO, "safe_misconfig_audit start", target=target_url)
    session = create_stealth_session("safe-audit")
    findings: dict[str, Any] = {"target": target_url, "issues": []}

    try:
        resp = session.get(target_url, timeout=8)
        h_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing = [r for r in _SECURITY_HEADERS_REQUIRED if r not in h_lower]
        if missing:
            findings["issues"].append(
                {
                    "type": "missing_security_headers",
                    "missing": missing,
                }
            )
        # Also check for Server/X-Powered-By disclosure
        for disclosure_header in ("server", "x-powered-by"):
            if disclosure_header in h_lower:
                findings["issues"].append(
                    {
                        "type": "version_disclosure",
                        "header": disclosure_header,
                        "value": h_lower[disclosure_header],
                    }
                )
    except Exception as exc:
        log_swallowed_exception("misconfig_audit root", exc)

    for path in _MGMT_PATHS:
        url = urllib.parse.urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                findings["issues"].append(
                    {
                        "type": "exposed_management_endpoint",
                        "path": path,
                        "status_code": 200,
                    }
                )
        except Exception as exc:
            log_swallowed_exception(f"misconfig_audit {path}", exc)

    log_event(logging.INFO, "safe_misconfig_audit complete", issues=len(findings["issues"]))
    return findings


# ---------------------------------------------------------------------------
# safe_full_audit
# ---------------------------------------------------------------------------


def safe_full_audit(target_url: str) -> dict[str, Any]:
    """Run all four passive audits and compute an overall risk level.

    Sub-audits:
    - ``safe_encoding_audit``    — server-side decoding behaviour
    - ``safe_log_audit``         — Log4j version indicators
    - ``safe_dependency_audit``  — library leakage via actuator/swagger
    - ``safe_misconfig_audit``   — missing security headers, exposed management

    Risk level rules:
    - **high**: log risk=high OR ≥3 misconfig issues
    - **medium**: any encoding observation, dependency leak, or misconfig
    - **low**: none of the above

    Args:
        target_url: Base URL to audit.

    Returns:
        Structured audit result dict with ``overall_risk`` and sub-audit results.
    """
    from spring2shell.audit.log_audit import run_log_audit, safe_log_audit

    encoding = safe_encoding_audit(target_url)
    log_risk_findings = run_log_audit(target_url)
    log_risk_full = safe_log_audit(target_url)
    deps = safe_dependency_audit(target_url)
    misconfig = safe_misconfig_audit(target_url)

    log_risk_level = log_risk_full.get("risk", "low")
    misconfig_count = len(misconfig.get("issues", []))
    dep_leak_count = len(deps.get("leaks", []))
    encoding_observations = sum(1 for e in encoding if e.get("decoding_observations"))

    if log_risk_level == "high" or misconfig_count >= 3:
        overall_risk = "high"
    elif encoding_observations > 0 or dep_leak_count > 0 or misconfig_count > 0:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    strict_summary = {
        "encoding_endpoints_with_observations": encoding_observations,
        "log_risk": log_risk_level,
        "dependency_leak_count": dep_leak_count,
        "misconfig_issue_count": misconfig_count,
        "overall_risk": overall_risk,
    }

    log_event(logging.INFO, "safe_full_audit complete", target=target_url, risk=overall_risk)

    return {
        "schema_version": "1.0",
        "schema_type": "react2shell_safe_full_audit",
        "target": target_url,
        "encoding": encoding,
        "log_risk": log_risk_full,
        "log_findings": list(log_risk_findings),
        "dependency_leakage": deps,
        "misconfiguration": misconfig,
        "strict_summary": strict_summary,
    }


def run_safe_audit(target_url: str) -> list[dict[str, Any]]:
    """Run all four passive audits and return a list of standard findings.

    Args:
        target_url: Base URL to audit.

    Returns:
        List of findings.
    """
    from spring2shell.audit.log_audit import run_log_audit
    from spring2shell.core.reporter import build_finding

    findings: list[dict[str, Any]] = []

    # 1. Encoding audit
    try:
        encoding_results = safe_encoding_audit(target_url)
        for res in encoding_results:
            endpoint = res.get("endpoint", target_url)
            observations = res.get("decoding_observations", [])
            for obs in observations:
                method = obs.get("method", "POST")
                variant = obs.get("variant", "plain")
                reflected_plain = obs.get("reflected_plain", False)
                reflected_encoded = obs.get("reflected_encoded", False)
                evidence = f"Marker variant '{variant}' reflected in response (plain={reflected_plain}, encoded={reflected_encoded})"
                finding = build_finding(
                    url=target_url,
                    endpoint=endpoint,
                    status="unverified",
                    confidence="medium",
                    reason="DECODING_OBSERVATION",
                    evidence=evidence,
                    method=method,
                    extra={"variant": variant, "reflected_plain": reflected_plain, "reflected_encoded": reflected_encoded}
                )
                findings.append(finding)
    except Exception as exc:
        log_swallowed_exception("run_safe_audit encoding", exc)

    # 2. Log4j audit
    try:
        log4j_findings = run_log_audit(target_url)
        findings.extend(log4j_findings)
    except Exception as exc:
        log_swallowed_exception("run_safe_audit log4j", exc)

    # 3. Dependency audit
    try:
        deps = safe_dependency_audit(target_url)
        for leak in deps.get("leaks", []):
            path = leak.get("path", "")
            endpoint = urllib.parse.urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            status_code = leak.get("status_code")
            indicators = leak.get("indicators", [])
            evidence = f"Dependency leakage detected via indicators: {', '.join(indicators)}"
            finding = build_finding(
                url=target_url,
                endpoint=endpoint,
                status="unverified",
                confidence="medium",
                reason="DEPENDENCY_LEAKAGE",
                evidence=evidence,
                method="GET",
                status_code=status_code,
                extra={"indicators": indicators}
            )
            findings.append(finding)
    except Exception as exc:
        log_swallowed_exception("run_safe_audit dependency", exc)

    # 4. Misconfiguration audit
    try:
        misconfig = safe_misconfig_audit(target_url)
        for issue in misconfig.get("issues", []):
            issue_type = issue.get("type")
            if issue_type == "missing_security_headers":
                missing = issue.get("missing", [])
                evidence = f"Missing security headers: {', '.join(missing)}"
                finding = build_finding(
                    url=target_url,
                    endpoint=target_url,
                    status="unverified",
                    confidence="low",
                    reason="MISSING_SECURITY_HEADERS",
                    evidence=evidence,
                    method="GET",
                    extra={"missing_headers": missing}
                )
                findings.append(finding)
            elif issue_type == "version_disclosure":
                header = issue.get("header", "")
                value = issue.get("value", "")
                evidence = f"Version disclosure via header '{header}': {value}"
                finding = build_finding(
                    url=target_url,
                    endpoint=target_url,
                    status="unverified",
                    confidence="low",
                    reason="VERSION_DISCLOSURE",
                    evidence=evidence,
                    method="GET",
                    extra={"header": header, "value": value}
                )
                findings.append(finding)
            elif issue_type == "exposed_management_endpoint":
                path = issue.get("path", "")
                endpoint = urllib.parse.urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
                status_code = issue.get("status_code", 200)
                evidence = f"Exposed management endpoint at {path}"
                finding = build_finding(
                    url=target_url,
                    endpoint=endpoint,
                    status="unverified",
                    confidence="medium",
                    reason="EXPOSED_MANAGEMENT_ENDPOINT",
                    evidence=evidence,
                    method="GET",
                    status_code=status_code
                )
                findings.append(finding)
    except Exception as exc:
        log_swallowed_exception("run_safe_audit misconfig", exc)

    return findings

