"""
Base class for dynamic scanner and exploitation plugins in spring2shell.
"""

from __future__ import annotations

from typing import Any
import requests


class BasePlugin:
    """Base class for all vulnerability scanner and exploitation plugins."""

    name: str = ""
    cve_id: str | None = None
    description: str = ""

    def check(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Scan the endpoint for the vulnerability.

        Args:
            session: Active Requests Session.
            target: Base target URL.
            endpoint: Full URL of the endpoint to check.
            headers: Dict of requests headers.

        Returns:
            Normalised finding dict if vulnerable, None otherwise.
        """
        raise NotImplementedError

    def exploit(
        self,
        session: requests.Session,
        target: str,
        endpoint: str,
        headers: dict[str, str],
        command: str,
    ) -> str | None:
        """Execute command on target endpoint.

        Args:
            session: Active Requests Session.
            target: Base target URL.
            endpoint: Full URL of the endpoint to exploit.
            headers: Dict of requests headers.
            command: OS command to execute.

        Returns:
            Exploit execution output if successful, None otherwise.
        """
        raise NotImplementedError
