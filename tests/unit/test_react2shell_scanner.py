"""
Unit tests for react2shell/scanner.py (new modular implementation).
Tests scan_react2shell() and supporting helpers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests


def _make_response(
    text: str = "",
    status: int = 200,
    extra_headers: dict | None = None,
) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    headers = {"Content-Type": "text/plain"}
    if extra_headers:
        headers.update(extra_headers)
    r.headers = headers
    return r


def _make_session(text: str = "ok", status: int = 400, get_text: str = ""):
    """Create a mock session where GET returns get_text and POST returns text."""
    session = MagicMock()
    get_resp = _make_response(get_text, status)
    post_resp = _make_response(text, status)
    session.get.return_value = get_resp
    session.post.return_value = post_resp
    return session


# ---------------------------------------------------------------------------
# _extract_next_data_routes
# ---------------------------------------------------------------------------


class TestExtractNextDataRoutes:
    def test_extracts_page_from_next_data(self):
        from spring2shell.react2shell.scanner import _extract_next_data_routes

        html = '<script id="__NEXT_DATA__">{"page":"/products","props":{},"buildId":"abc"}</script>'
        routes = _extract_next_data_routes(html, "http://t.example")
        assert "/products" in routes

    def test_returns_empty_on_missing_next_data(self):
        from spring2shell.react2shell.scanner import _extract_next_data_routes

        html = "<html><body>Regular page</body></html>"
        routes = _extract_next_data_routes(html, "http://t.example")
        assert routes == []

    def test_skips_internal_pages(self):
        from spring2shell.react2shell.scanner import _extract_next_data_routes

        html = '<script id="__NEXT_DATA__">{"page":"/_app","props":{}}</script>'
        routes = _extract_next_data_routes(html, "http://t.example")
        assert "/_app" not in routes

    def test_handles_invalid_json(self):
        from spring2shell.react2shell.scanner import _extract_next_data_routes

        html = '<script id="__NEXT_DATA__">NOT VALID JSON</script>'
        routes = _extract_next_data_routes(html, "http://t.example")
        assert routes == []


# ---------------------------------------------------------------------------
# scan_react2shell
# ---------------------------------------------------------------------------


class TestScanReact2Shell:
    def test_returns_list(self):
        from spring2shell.react2shell.scanner import scan_react2shell

        session = _make_session("clean response", 200)
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        assert isinstance(result, list)

    def test_spel_probe_indicator_detected(self):
        """Response containing '49' (7*7) triggers SpEL candidate finding."""
        from spring2shell.react2shell.scanner import scan_react2shell

        session = _make_session("result is 49 here", 200)
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        assert any(f.get("status") in ("unverified", "confirmed") for f in result)

    def test_graphql_introspection_detected(self):
        """Response with __Schema triggers introspection finding."""
        from spring2shell.react2shell.scanner import scan_react2shell

        introspection_resp = _make_response(
            '{"data":{"__schema":{"types":[{"name":"__Schema"}]}}}', 200
        )
        clean_resp = _make_response("clean", 404)
        session = MagicMock()
        session.get.return_value = clean_resp
        session.post.return_value = introspection_resp
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        assert any("INTROSPECTION" in f.get("reason", "") for f in result)

    def test_interrupted_stops_early(self):
        """is_interrupted=True should stop scanning quickly."""
        from spring2shell.react2shell.scanner import scan_react2shell

        session = _make_session()
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=True):
            result = scan_react2shell("http://t.example")
        assert isinstance(result, list)

    def test_connection_error_swallowed(self):
        """Network errors during probing should not crash the scanner."""
        from spring2shell.react2shell.scanner import scan_react2shell

        session = MagicMock()
        session.get.side_effect = ConnectionError("refused")
        session.post.side_effect = ConnectionError("refused")
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        assert isinstance(result, list)

    def test_finding_has_required_keys(self):
        """Any finding must have the required standard keys."""
        from spring2shell.react2shell.scanner import scan_react2shell

        session = _make_session("__Schema types", 200)
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        for f in result:
            for key in ("url", "endpoint", "status", "evidence", "method"):
                assert key in f, f"Missing key '{key}' in finding: {f}"

    def test_nextjs_detected_from_header(self):
        """Next.js detection from response headers enables additional probing."""
        from spring2shell.react2shell.scanner import scan_react2shell

        session = MagicMock()
        get_resp = _make_response("page", 200, {"x-powered-by": "Next.js"})
        post_resp = _make_response("ok", 200)
        session.get.return_value = get_resp
        session.post.return_value = post_resp
        with patch(
            "spring2shell.react2shell.scanner.create_stealth_session", return_value=session
        ), patch("spring2shell.react2shell.scanner.get_random_headers", return_value={}), patch(
            "spring2shell.react2shell.scanner.apply_auth"
        ), patch("spring2shell.react2shell.scanner.rate_limit_acquire"), patch(
            "spring2shell.react2shell.scanner.audit_log"
        ), patch("spring2shell.react2shell.scanner.is_interrupted", return_value=False):
            result = scan_react2shell("http://t.example")
        # No assertion on count — just verify it completes without error
        assert isinstance(result, list)
