"""
Unit tests for react2shell/scanner.py:
- _build_react2shell_body
- scan_react2shell
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests


def _make_response(text: str = "", status: int = 200,
                   extra_headers: dict | None = None) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    headers = {"Content-Type": "text/plain"}
    if extra_headers:
        headers.update(extra_headers)
    r.headers = headers
    return r


# ---------------------------------------------------------------------------
# _build_react2shell_body
# ---------------------------------------------------------------------------

class TestBuildReact2ShellBody:
    def test_returns_tuple_of_three(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        body, headers, expected = _build_react2shell_body()
        assert isinstance(body, str)
        assert isinstance(headers, dict)
        assert isinstance(expected, str)

    def test_expected_is_math_result(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        _, _, expected = _build_react2shell_body()
        assert expected == "11111"  # 41 * 271

    def test_safe_mode_omits_spel(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        body, _, _ = _build_react2shell_body(safe_mode=True)
        assert "T(java.lang.Runtime)" not in body
        assert "SAFE-CHECK" in body

    def test_vercel_bypass_contains_v0(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        body, _, _ = _build_react2shell_body(vercel_bypass=True, padding_kb=1)
        assert "V0" in body

    def test_headers_contain_next_action(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        _, headers, _ = _build_react2shell_body()
        assert "next-action" in headers
        assert "Content-Type" in headers
        assert "multipart/form-data" in headers["Content-Type"]

    def test_padding_affects_body_size(self) -> None:
        from spring2shell.react2shell.scanner import _build_react2shell_body
        body_small, _, _ = _build_react2shell_body(padding_kb=1)
        body_large, _, _ = _build_react2shell_body(padding_kb=10)
        assert len(body_large) > len(body_small)


# ---------------------------------------------------------------------------
# scan_react2shell
# ---------------------------------------------------------------------------

class TestScanReact2Shell:
    def _make_session(self, text: str = "ok", status: int = 400):
        session = MagicMock()
        resp = _make_response(text, status)
        session.post.return_value = resp
        return session

    def test_returns_list(self) -> None:
        from spring2shell.react2shell.scanner import scan_react2shell

        session = self._make_session()
        with patch("spring2shell.react2shell.scanner.create_stealth_session", return_value=session), \
             patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), \
             patch("spring2shell.react2shell.scanner.waf_engine") as mock_waf, \
             patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            result = scan_react2shell("http://t.example", padding_kb=1)
        assert isinstance(result, list)

    def test_confirmed_when_math_marker_reflected(self) -> None:
        from spring2shell.react2shell.scanner import scan_react2shell

        # The expected marker is "11111" (41*271)
        session = self._make_session("11111", 200)
        resp = _make_response("11111", 200, {"X-Action-Redirect": "11111"})
        session.post.return_value = resp

        with patch("spring2shell.react2shell.scanner.create_stealth_session", return_value=session), \
             patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), \
             patch("spring2shell.react2shell.scanner.waf_engine") as mock_waf, \
             patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            result = scan_react2shell("http://t.example", padding_kb=1)

        confirmed = [r for r in result if r.get("status") == "confirmed"]
        assert len(confirmed) >= 1

    def test_interrupted_returns_empty(self) -> None:
        from spring2shell.react2shell.scanner import scan_react2shell

        session = self._make_session()
        with patch("spring2shell.react2shell.scanner.create_stealth_session", return_value=session), \
             patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), \
             patch("spring2shell.react2shell.scanner.waf_engine") as mock_waf, \
             patch("spring2shell.react2shell.scanner.is_interrupted", return_value=True):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            result = scan_react2shell("http://t.example", padding_kb=1)
        assert result == []

    def test_connection_error_swallowed(self) -> None:
        from spring2shell.react2shell.scanner import scan_react2shell

        session = MagicMock()
        session.post.side_effect = ConnectionError("refused")

        with patch("spring2shell.react2shell.scanner.create_stealth_session", return_value=session), \
             patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), \
             patch("spring2shell.react2shell.scanner.waf_engine") as mock_waf, \
             patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            result = scan_react2shell("http://t.example", padding_kb=1)
        assert isinstance(result, list)

    def test_finding_dict_has_required_keys(self) -> None:
        from spring2shell.react2shell.scanner import scan_react2shell

        resp = _make_response("11111", 200, {"X-Action-Redirect": "11111"})
        session = MagicMock()
        session.post.return_value = resp

        with patch("spring2shell.react2shell.scanner.create_stealth_session", return_value=session), \
             patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), \
             patch("spring2shell.react2shell.scanner.waf_engine") as mock_waf, \
             patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            mock_waf.apply.side_effect = lambda b, h: (b, h)
            result = scan_react2shell("http://t.example", padding_kb=1)

        for f in result:
            for key in ("url", "endpoint", "status", "evidence", "method"):
                assert key in f
