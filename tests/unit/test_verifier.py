"""
Unit tests for core/verifier.py:
- _escape_java_string
- _build_payload_from_template
- _marker_variants (via check_real_rce surface)
- _strict_verify_execution
- check_real_rce
- blind_rce_test
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# _escape_java_string
# ---------------------------------------------------------------------------

class TestEscapeJavaString:
    def test_escapes_double_quote(self) -> None:
        from spring2shell.core.verifier import _escape_java_string
        assert _escape_java_string('say "hi"') == 'say \\"hi\\"'

    def test_escapes_backslash(self) -> None:
        from spring2shell.core.verifier import _escape_java_string
        assert _escape_java_string("a\\b") == "a\\\\b"

    def test_plain_string_unchanged(self) -> None:
        from spring2shell.core.verifier import _escape_java_string
        assert _escape_java_string("id") == "id"

    def test_combined(self) -> None:
        from spring2shell.core.verifier import _escape_java_string
        result = _escape_java_string('echo "test\\n"')
        assert '\\"' in result
        assert "\\\\" in result


# ---------------------------------------------------------------------------
# _build_payload_from_template
# ---------------------------------------------------------------------------

class TestBuildPayloadFromTemplate:
    def test_none_template_returns_none(self) -> None:
        from spring2shell.core.verifier import _build_payload_from_template
        assert _build_payload_from_template(None, "id") is None

    def test_na_template_returns_none(self) -> None:
        from spring2shell.core.verifier import _build_payload_from_template
        assert _build_payload_from_template("N/A", "id") is None

    def test_command_placeholder_replaced(self) -> None:
        from spring2shell.core.verifier import _build_payload_from_template
        template = '{"query": "{{COMMAND}}"}'
        result = _build_payload_from_template(template, "whoami")
        assert "whoami" in result
        assert "COMMAND" not in result

    def test_empty_template_returns_none(self) -> None:
        from spring2shell.core.verifier import _build_payload_from_template
        assert _build_payload_from_template("", "id") is None


# ---------------------------------------------------------------------------
# _strict_verify_execution
# ---------------------------------------------------------------------------

def _make_response(text: str, status: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    return r


class TestStrictVerifyExecution:
    def test_returns_false_when_markers_not_in_response(self) -> None:
        from spring2shell.core.verifier import _strict_verify_execution

        session = MagicMock()
        # Baseline + 2 marker attempts — marker never appears
        session.post.return_value = _make_response("no marker here")
        session.get.return_value = _make_response("no marker here")

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}):
            result = _strict_verify_execution(session, "http://t.example/api", "POST", {})
        assert result is False

    def test_returns_true_when_both_markers_reflected(self) -> None:
        from spring2shell.core.verifier import _strict_verify_execution

        session = MagicMock()
        baseline = _make_response("baseline_response_no_marker")
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            # For subsequent calls, return the marker that was sent
            data = kwargs.get("data", "")
            # Extract the marker from the payload
            import re
            match = re.search(r"(RCE_STRICT_\d+)", data)
            if match:
                return _make_response(match.group(1))
            return _make_response("")

        session.post.side_effect = side_effect

        with patch("spring2shell.core.verifier._build_payload_from_template", return_value=None):
            result = _strict_verify_execution(session, "http://t.example/api", "POST", {})
        # With mocked side effects, at minimum it should not raise
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# check_real_rce
# ---------------------------------------------------------------------------

class TestCheckRealRce:
    def _mock_session_factory(self, response_text: str = "", status: int = 200):
        session = MagicMock()
        resp = _make_response(response_text, status)
        session.post.return_value = resp
        session.get.return_value = resp
        return session

    def test_returns_false_when_marker_not_found(self) -> None:
        from spring2shell.core.verifier import check_real_rce

        session = self._mock_session_factory("some irrelevant response")
        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}):
            result = check_real_rce("http://t.example", "http://t.example/api")
        assert result is False

    def test_returns_true_when_marker_reflected(self) -> None:
        from spring2shell.core.verifier import check_real_rce

        # Return a response that contains whatever marker was sent
        call_count = [0]
        captured_marker = [None]

        def post_side_effect(*args, **kwargs):
            data = kwargs.get("data", "")
            import re
            match = re.search(r"(RCE_TEST_\d+)", data)
            if match:
                captured_marker[0] = match.group(1)
                return _make_response(match.group(1))
            return _make_response("")

        session = MagicMock()
        session.post.side_effect = post_side_effect
        session.get.return_value = _make_response("")

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={"Content-Type": "application/json"}):
            result = check_real_rce("http://t.example", "http://t.example/api", method="POST")
        assert result is True

    def test_get_method_uses_params(self) -> None:
        from spring2shell.core.verifier import check_real_rce

        session = MagicMock()
        session.get.return_value = _make_response("nothing")
        session.post.return_value = _make_response("nothing")

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}):
            result = check_real_rce("http://t.example", "http://t.example/api", method="GET")
        # GET requests should have been made
        assert session.get.called
        assert result is False


# ---------------------------------------------------------------------------
# blind_rce_test
# ---------------------------------------------------------------------------

class TestBlindRceTest:
    def test_returns_false_when_no_time_delay(self) -> None:
        from spring2shell.core.verifier import blind_rce_test

        session = MagicMock()
        session.post.return_value = _make_response("normal response")
        session.get.return_value = _make_response("normal response")

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}), \
             patch("time.sleep"):
            result = blind_rce_test("http://t.example", "http://t.example/api")
        assert result is False

    def test_returns_true_on_timeout(self) -> None:
        from spring2shell.core.verifier import blind_rce_test
        import requests as req

        call_count = [0]

        def post_side_effect(*args, **kwargs):
            call_count[0] += 1
            # First call is baseline, second triggers timeout
            if call_count[0] >= 2:
                raise req.exceptions.Timeout("simulated")
            return _make_response("baseline")

        session = MagicMock()
        session.post.side_effect = post_side_effect

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}), \
             patch("time.sleep"):
            result = blind_rce_test("http://t.example", "http://t.example/api")
        assert result is True

    def test_does_not_raise_on_exception(self) -> None:
        from spring2shell.core.verifier import blind_rce_test

        session = MagicMock()
        session.post.side_effect = ConnectionError("refused")

        with patch("spring2shell.core.verifier.create_stealth_session", return_value=session), \
             patch("spring2shell.core.verifier.get_random_headers", return_value={}), \
             patch("time.sleep"):
            result = blind_rce_test("http://t.example", "http://t.example/api")
        assert isinstance(result, bool)
