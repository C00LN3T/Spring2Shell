"""
Unit tests for the WAF Diagnostic Profiler module.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from spring2shell.core.waf_profiler import profile_waf


class TestWAFProfiler(unittest.TestCase):
    @patch("spring2shell.core.waf_profiler.create_stealth_session")
    @patch("spring2shell.core.waf_profiler.get_random_headers")
    def test_profile_waf_normal_flow(self, mock_headers, mock_create_session):
        mock_headers.return_value = {"User-Agent": "Test"}
        session = MagicMock()
        mock_create_session.return_value = session

        # Mock GET baseline response
        resp_baseline = MagicMock()
        resp_baseline.status_code = 200
        resp_baseline.text = "OK"
        session.get.return_value = resp_baseline
        session.request.return_value = resp_baseline
        session.post.return_value = resp_baseline
        session.head.return_value = resp_baseline

        report = profile_waf("http://example.com")
        self.assertEqual(report["target"], "http://example.com")
        self.assertEqual(report["baseline_status"], 200)
        self.assertFalse(report["methods"]["GET"]["blocked"])
        self.assertFalse(report["characters_query"]["{"]["blocked"])
        self.assertFalse(report["characters_json"]["{"]["blocked"])

    @patch("spring2shell.core.waf_profiler.create_stealth_session")
    @patch("spring2shell.core.waf_profiler.get_random_headers")
    def test_profile_waf_blocks(self, mock_headers, mock_create_session):
        mock_headers.return_value = {"User-Agent": "Test"}
        session = MagicMock()
        mock_create_session.return_value = session

        # Baseline is 200
        resp_baseline = MagicMock()
        resp_baseline.status_code = 200
        resp_baseline.text = "OK"

        # Blocked (e.g. 403 Forbidden)
        resp_blocked = MagicMock()
        resp_blocked.status_code = 403
        resp_blocked.text = "Forbidden"

        def mock_get(url, *args, **kwargs):
            if "%7B" in url or "%7D" in url:
                return resp_blocked
            return resp_baseline

        session.get.side_effect = mock_get
        session.request.return_value = resp_baseline
        session.post.return_value = resp_baseline
        session.head.return_value = resp_baseline

        report = profile_waf("http://example.com")
        self.assertTrue(report["characters_query"]["{"]["blocked"])
        self.assertEqual(report["characters_query"]["{"]["status_code"], 403)
        self.assertFalse(report["characters_query"]["["]["blocked"])
