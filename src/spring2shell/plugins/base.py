"""
Base class for dynamic scanner and exploitation plugins in spring2shell.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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

    async def async_check(
        self,
        session: Any,
        target: str,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Scan the endpoint asynchronously.

        By default, runs the legacy synchronous check() method in a separate thread.
        """
        import asyncio

        import requests

        from spring2shell.core.session import create_stealth_session

        if isinstance(session, requests.Session):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.check, session, target, endpoint, headers)

        def _run_sync() -> dict[str, Any] | None:
            sync_session = create_stealth_session()
            try:
                return self.check(sync_session, target, endpoint, headers)
            finally:
                sync_session.close()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run_sync)

    async def async_exploit(
        self,
        session: Any,
        target: str,
        endpoint: str,
        headers: dict[str, str],
        command: str,
    ) -> str | None:
        """Execute command asynchronously on target.

        By default, runs the legacy synchronous exploit() method in a separate thread.
        """
        import asyncio

        import requests

        from spring2shell.core.session import create_stealth_session

        if isinstance(session, requests.Session):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self.exploit, session, target, endpoint, headers, command
            )

        def _run_sync() -> str | None:
            sync_session = create_stealth_session()
            try:
                return self.exploit(sync_session, target, endpoint, headers, command)
            finally:
                sync_session.close()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run_sync)
