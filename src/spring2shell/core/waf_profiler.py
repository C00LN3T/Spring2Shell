"""
WAF Profiler — safely analyze server-side request filtering (WAF) behavior
using benign diagnostic probes.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.logging import log_event


def profile_waf(target_url: str) -> dict[str, Any]:
    """safely profile a target URL to check which characters and HTTP methods trigger WAF blocks.

    Probes are completely benign and do not contain exploit payloads.

    Args:
        target_url: The target base URL.

    Returns:
        Dict mapping methods and characters to block statuses.
    """
    log_event(logging.INFO, "Starting WAF diagnostic profiling", target=target_url)
    session = create_stealth_session()
    headers = get_random_headers()

    # Establish baseline GET response status
    baseline_status = 200
    try:
        baseline_resp = session.get(target_url, headers=headers.copy(), timeout=5)
        baseline_status = baseline_resp.status_code
    except Exception as exc:
        log_event(logging.WARNING, f"Baseline request failed: {exc}. Using 200 as baseline.")

    blocked_methods: dict[str, Any] = {}
    blocked_chars_query: dict[str, Any] = {}
    blocked_chars_json: dict[str, Any] = {}

    # Test HTTP methods
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    for m in methods:
        try:
            if m == "GET":
                resp = session.get(target_url, headers=headers.copy(), timeout=5)
            elif m == "HEAD":
                resp = session.head(target_url, headers=headers.copy(), timeout=5)
            else:
                resp = session.request(m, target_url, headers=headers.copy(), timeout=5)
            status = resp.status_code
            blocked = status in (401, 403, 405) or (status != baseline_status and status >= 400)
            blocked_methods[m] = {
                "blocked": blocked,
                "status_code": status,
                "reason": "HTTP Error status" if blocked else "Allowed/Normal response",
            }
        except Exception as exc:
            blocked_methods[m] = {
                "blocked": True,
                "status_code": None,
                "reason": f"Connection error/timeout: {exc}",
            }

    # Test diagnostic characters
    test_chars = ["{", "}", "[", "]", "(", ")", "'", '"', "$", "<", ">", ";", "|", "`", "\\"]

    # Character in query param
    for char in test_chars:
        # Benign test query: ?test=char
        url = urllib.parse.urljoin(target_url, f"?test={urllib.parse.quote(char)}")
        try:
            resp = session.get(url, headers=headers.copy(), timeout=5)
            status = resp.status_code
            blocked = status in (401, 403) or (status != baseline_status and status >= 400)
            blocked_chars_query[char] = {
                "blocked": blocked,
                "status_code": status,
                "reason": "HTTP Block status" if blocked else "Allowed",
            }
        except Exception as exc:
            blocked_chars_query[char] = {
                "blocked": True,
                "status_code": None,
                "reason": f"Connection drop: {exc}",
            }

    # Character in JSON body
    for char in test_chars:
        json_data = {"test": f"benign_{char}_test"}
        try:
            # Benign POST request
            req_headers = headers.copy()
            req_headers["Content-Type"] = "application/json"
            resp = session.post(target_url, json=json_data, headers=req_headers, timeout=5)
            status = resp.status_code
            blocked = status in (401, 403) or (status != baseline_status and status >= 400)
            blocked_chars_json[char] = {
                "blocked": blocked,
                "status_code": status,
                "reason": "HTTP Block status" if blocked else "Allowed",
            }
        except Exception as exc:
            blocked_chars_json[char] = {
                "blocked": True,
                "status_code": None,
                "reason": f"Connection drop: {exc}",
            }

    report = {
        "target": target_url,
        "baseline_status": baseline_status,
        "methods": blocked_methods,
        "characters_query": blocked_chars_query,
        "characters_json": blocked_chars_json,
    }

    log_event(logging.INFO, "WAF diagnostic profiling complete", target=target_url)
    return report


def print_waf_profile(report: dict[str, Any]) -> None:
    """Print the WAF profile report in a clean console format."""
    print("=" * 60)
    print(f" WAF DIAGNOSTIC PROFILE REPORT FOR: {report['target']}")
    print(f" Baseline GET Status Code: {report['baseline_status']}")
    print("=" * 60)

    print("\n[+] HTTP Methods Status:")
    for method, res in report["methods"].items():
        block_str = "❌ BLOCKED" if res["blocked"] else "✅ ALLOWED"
        status_str = f"(HTTP {res['status_code']})" if res["status_code"] else "(Connection Drop)"
        print(f"  {method:<10} : {block_str:<10} {status_str} - {res['reason']}")

    print("\n[+] Characters in Query Parameters:")
    for char, res in report["characters_query"].items():
        block_str = "❌ BLOCKED" if res["blocked"] else "✅ ALLOWED"
        status_str = f"(HTTP {res['status_code']})" if res["status_code"] else "(Connection Drop)"
        print(f"  '{char}'        : {block_str:<10} {status_str} - {res['reason']}")

    print("\n[+] Characters in JSON POST Body:")
    for char, res in report["characters_json"].items():
        block_str = "❌ BLOCKED" if res["blocked"] else "✅ ALLOWED"
        status_str = f"(HTTP {res['status_code']})" if res["status_code"] else "(Connection Drop)"
        print(f"  '{char}'        : {block_str:<10} {status_str} - {res['reason']}")
    print("=" * 60)
