"""
Unit tests for core/evasion_runner.py:
- aggressive_waf_bypass
- find_working_endpoint
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests


def _make_response(
    text: str = "", status: int = 200, content_type: str = "application/json"
) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    r.headers = {"Content-Type": content_type}
    return r


# ---------------------------------------------------------------------------
# aggressive_waf_bypass
# ---------------------------------------------------------------------------


class TestAggressiveWafBypass:
    def _patched_session(self, status: int = 200, text: str = "ok"):
        session = MagicMock()
        resp = _make_response(text, status)
        session.post.return_value = resp
        session.get.return_value = resp
        session.request.return_value = resp
        return session

    def test_returns_list(self) -> None:
        from spring2shell.core.evasion_runner import aggressive_waf_bypass

        session = self._patched_session(200, "normal output")
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch("time.sleep"):
            result = aggressive_waf_bypass("http://t.example", "http://t.example/api", "id")
        assert isinstance(result, list)

    def test_blocked_responses_not_in_results(self) -> None:
        from spring2shell.core.evasion_runner import aggressive_waf_bypass

        session = self._patched_session(403)
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch("time.sleep"):
            result = aggressive_waf_bypass("http://t.example", "http://t.example/api")
        assert result == []

    def test_early_exit_on_success_with_indicators(self) -> None:
        from spring2shell.core.evasion_runner import aggressive_waf_bypass

        session = self._patched_session(200, "uid=0(root) gid=0(root)")
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch("time.sleep"):
            result = aggressive_waf_bypass("http://t.example", "http://t.example/api", "id")
        # Should return early after first technique with 200 + output indicators
        assert len(result) >= 1
        assert result[0]["status_code"] == 200
        assert "uid=" in result[0]["indicators"]

    def test_interrupted_returns_early(self) -> None:
        from spring2shell.core.evasion_runner import aggressive_waf_bypass

        session = self._patched_session(200)
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=True
        ):
            result = aggressive_waf_bypass("http://t.example", "http://t.example/api")
        assert result == []

    def test_exception_does_not_raise(self) -> None:
        from spring2shell.core.evasion_runner import aggressive_waf_bypass

        session = MagicMock()
        session.request.side_effect = ConnectionError("refused")
        session.post.side_effect = ConnectionError("refused")
        session.get.side_effect = ConnectionError("refused")

        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch("time.sleep"):
            result = aggressive_waf_bypass("http://t.example", "http://t.example/api")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# find_working_endpoint
# ---------------------------------------------------------------------------


class TestFindWorkingEndpoint:
    def _api_session(self):
        session = MagicMock()
        resp_get = _make_response('{"data": "graphql"}', 200, "application/json")
        resp_post = _make_response('{"errors": []}', 200, "application/json")
        session.get.return_value = resp_get
        session.post.return_value = resp_post
        return session

    def test_returns_list(self) -> None:
        from spring2shell.core.evasion_runner import find_working_endpoint

        session = self._api_session()
        mock_endpoints = ["/api/graphql", "/graphql"]
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch(
            "spring2shell.discovery.endpoints.load_endpoints", return_value=mock_endpoints
        ), patch("time.sleep"):
            result = find_working_endpoint("http://t.example", limit=2)
        assert isinstance(result, list)

    def test_limit_respected(self) -> None:
        from spring2shell.core.evasion_runner import find_working_endpoint

        # 10 endpoints available, limit=3
        session = self._api_session()
        many_endpoints = [f"/ep{i}" for i in range(10)]
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch(
            "spring2shell.discovery.endpoints.load_endpoints", return_value=many_endpoints
        ), patch("time.sleep"):
            find_working_endpoint("http://t.example", limit=3)
        # At most 3 endpoints were probed (GET + POST each)
        assert session.get.call_count <= 3

    def test_connection_errors_swallowed(self) -> None:
        from spring2shell.core.evasion_runner import find_working_endpoint

        session = MagicMock()
        session.get.side_effect = ConnectionError("refused")
        session.post.side_effect = ConnectionError("refused")

        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch("spring2shell.discovery.endpoints.load_endpoints", return_value=["/api"]), patch(
            "time.sleep"
        ):
            result = find_working_endpoint("http://t.example")
        assert isinstance(result, list)  # errors swallowed, empty list returned

    def test_result_dict_has_required_keys(self) -> None:
        from spring2shell.core.evasion_runner import find_working_endpoint

        session = self._api_session()
        with patch(
            "spring2shell.core.evasion_runner.create_stealth_session", return_value=session
        ), patch("spring2shell.core.evasion_runner.get_random_headers", return_value={}), patch(
            "spring2shell.core.evasion_runner.is_interrupted", return_value=False
        ), patch(
            "spring2shell.discovery.endpoints.load_endpoints", return_value=["/api/graphql"]
        ), patch("time.sleep"):
            result = find_working_endpoint("http://t.example", limit=1)
        for ep in result:
            assert "url" in ep
            assert "method" in ep
            assert "status" in ep
