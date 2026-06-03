"""
Unit tests for the asynchronous scanning engine.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from spring2shell.core.exploiter import async_cve_specific_scan, async_direct_exploit
from spring2shell.utils.async_network import create_async_session, send_async_request


class TestAsyncScanner(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    @patch("spring2shell.utils.async_network.get_auth_config")
    @patch("spring2shell.utils.async_network.get_proxy_url")
    def test_create_async_session(self, mock_get_proxy, mock_get_auth):
        auth = MagicMock()
        auth.bearer = "test_bearer"
        auth.headers = {"X-Custom": "Val"}
        auth.cookies = {"session": "abc"}
        auth.basic = ("user", "pass")
        mock_get_auth.return_value = auth
        mock_get_proxy.return_value = "http://proxy.example"

        async def run():
            session = create_async_session()
            self.assertEqual(session.headers.get("Authorization"), "Bearer test_bearer")
            self.assertEqual(session.headers.get("X-Custom"), "Val")
            self.assertEqual(session.proxy_url, "http://proxy.example")
            await session.close()

        self.loop.run_until_complete(run())

    @patch("spring2shell.utils.async_network.async_rate_limit_acquire")
    def test_send_async_request_retries(self, mock_rate_limit):
        async def run():
            session = MagicMock()

            # Setup a mock response that raises an error once, then returns success
            resp = AsyncMock()
            resp.status = 200
            resp.text = AsyncMock(return_value="OK")

            # Simulate a connection error on the first call, success on second
            call_count = 0

            async def mock_request(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    import aiohttp

                    raise aiohttp.ClientError("connection issue")
                return resp

            session.request = mock_request
            session.proxy_url = None

            res = await send_async_request(session, "GET", "http://example.com")
            self.assertEqual(res.status, 200)
            self.assertEqual(call_count, 2)

        self.loop.run_until_complete(run())

    @patch("spring2shell.core.exploiter.discover_endpoints")
    @patch("spring2shell.core.exploiter.tech_fingerprint")
    @patch("spring2shell.plugins.get_plugins")
    def test_async_direct_exploit_no_findings(
        self, mock_get_plugins, mock_fingerprint, mock_endpoints
    ):
        mock_fingerprint.return_value = []
        mock_endpoints.return_value = ["/api/graphql"]
        mock_get_plugins.return_value = {}  # No plugins for this test

        async def run():
            session = AsyncMock()
            resp = AsyncMock()
            resp.status = 404
            resp.text = AsyncMock(return_value="Not Found")
            session.request.return_value = resp

            findings = await async_direct_exploit("http://example.com", session=session)
            self.assertEqual(len(findings), 0)

        self.loop.run_until_complete(run())

    @patch("spring2shell.core.exploiter.discover_endpoints")
    @patch("spring2shell.plugins.get_plugins")
    def test_async_cve_specific_scan(self, mock_get_plugins, mock_endpoints):
        mock_endpoints.return_value = ["/"]

        # Mock a plugin
        mock_plugin_cls = MagicMock()
        mock_plugin = MagicMock()
        mock_plugin.cve_id = "CVE-2025-55182"

        async def mock_async_check(*args, **kwargs):
            return {"status": "confirmed", "cve": "CVE-2025-55182"}

        mock_plugin.async_check = mock_async_check
        mock_plugin_cls.return_value = mock_plugin
        mock_get_plugins.return_value = {"mock_plugin": mock_plugin_cls}

        async def run():
            session = AsyncMock()
            findings = await async_cve_specific_scan("http://example.com", session=session)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["cve"], "CVE-2025-55182")

        self.loop.run_until_complete(run())
