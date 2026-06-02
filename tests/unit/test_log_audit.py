"""
Unit tests for audit/log_audit.py:
- _parse_log4j_versions
- _is_log4j_vulnerable
- run_log_audit
- safe_log_audit
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# _parse_log4j_versions
# ---------------------------------------------------------------------------

class TestParseLog4jVersions:
    def test_extracts_version_from_log4j_core(self) -> None:
        from spring2shell.audit.log_audit import _parse_log4j_versions
        text = "log4j-core-2.14.1.jar found in classpath"
        versions = _parse_log4j_versions(text)
        assert "2.14.1" in versions

    def test_extracts_from_org_apache_logging(self) -> None:
        from spring2shell.audit.log_audit import _parse_log4j_versions
        text = 'org.apache.logging.log4j version="2.17.1"'
        versions = _parse_log4j_versions(text)
        assert "2.17.1" in versions

    def test_no_version_returns_empty(self) -> None:
        from spring2shell.audit.log_audit import _parse_log4j_versions
        text = "no version info here at all"
        versions = _parse_log4j_versions(text)
        assert versions == []

    def test_deduplicates_versions(self) -> None:
        from spring2shell.audit.log_audit import _parse_log4j_versions
        text = "log4j-core-2.14.1.jar log4j-api-2.14.1.jar"
        versions = _parse_log4j_versions(text)
        assert versions.count("2.14.1") == 1

    def test_case_insensitive(self) -> None:
        from spring2shell.audit.log_audit import _parse_log4j_versions
        text = "LOG4J-CORE-2.16.0"
        versions = _parse_log4j_versions(text)
        assert "2.16.0" in versions


# ---------------------------------------------------------------------------
# _is_log4j_vulnerable
# ---------------------------------------------------------------------------

class TestIsLog4jVulnerable:
    @pytest.mark.parametrize("version", [
        "2.0.0", "2.1.0", "2.14.1", "2.15.0",
    ])
    def test_vulnerable_versions(self, version: str) -> None:
        from spring2shell.audit.log_audit import _is_log4j_vulnerable
        assert _is_log4j_vulnerable(version) is True

    @pytest.mark.parametrize("version", [
        "2.16.0", "2.17.0", "2.17.1", "1.2.17", "3.0.0",
    ])
    def test_safe_versions(self, version: str) -> None:
        from spring2shell.audit.log_audit import _is_log4j_vulnerable
        assert _is_log4j_vulnerable(version) is False

    def test_invalid_version_returns_false(self) -> None:
        from spring2shell.audit.log_audit import _is_log4j_vulnerable
        assert _is_log4j_vulnerable("not-a-version") is False

    def test_empty_string_returns_false(self) -> None:
        from spring2shell.audit.log_audit import _is_log4j_vulnerable
        assert _is_log4j_vulnerable("") is False


# ---------------------------------------------------------------------------
# run_log_audit
# ---------------------------------------------------------------------------

def _make_response(text: str = "", status: int = 200) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    r.headers = {"Content-Type": "application/json"}
    return r


class TestRunLogAudit:
    def test_returns_list(self) -> None:
        from spring2shell.audit.log_audit import run_log_audit

        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response("", 404)):
            result = run_log_audit("http://t.example")
        assert isinstance(result, list)

    def test_finds_version_indicator(self) -> None:
        from spring2shell.audit.log_audit import run_log_audit

        body = '{"spring-boot": "2.7.0", "log4j-core": "2.14.1"}'
        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response(body, 200)):
            result = run_log_audit("http://t.example")

        # Should detect log4j-core pattern
        assert any(
            "log4j" in (f.get("evidence") or "").lower()
            or f.get("cve") == "CVE-2021-44228"
            for f in result
        )

    def test_vulnerable_version_creates_confirmed_finding(self) -> None:
        from spring2shell.audit.log_audit import run_log_audit

        body = "log4j-core 2.14.1 loaded"
        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response(body, 200)):
            result = run_log_audit("http://t.example")

        confirmed = [f for f in result if f.get("status") == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0]["cve"] == "CVE-2021-44228"

    def test_connection_error_swallowed(self) -> None:
        from spring2shell.audit.log_audit import run_log_audit

        with patch("spring2shell.audit.log_audit.requests.get",
                   side_effect=ConnectionError("refused")):
            result = run_log_audit("http://t.example")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# safe_log_audit
# ---------------------------------------------------------------------------

class TestSafeLogAudit:
    def test_returns_dict_with_required_keys(self) -> None:
        from spring2shell.audit.log_audit import safe_log_audit

        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response("", 404)):
            result = safe_log_audit("http://t.example")

        for key in ("target", "checked_paths", "versions_detected", "risk", "evidence"):
            assert key in result

    def test_risk_low_when_no_indicators(self) -> None:
        from spring2shell.audit.log_audit import safe_log_audit

        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response("no log4j here", 200)):
            result = safe_log_audit("http://t.example")
        assert result["risk"] in ("low", "medium")

    def test_risk_high_when_vulnerable_version(self) -> None:
        from spring2shell.audit.log_audit import safe_log_audit

        body = "log4j-core-2.14.1.jar is present"
        with patch("spring2shell.audit.log_audit.requests.get",
                   return_value=_make_response(body, 200)):
            result = safe_log_audit("http://t.example")

        assert result["risk"] == "high"
        assert "2.14.1" in result["versions_detected"]

    def test_accessible_actuator_adds_evidence(self) -> None:
        from spring2shell.audit.log_audit import safe_log_audit

        call_count = [0]
        def get_side(url, **kwargs):
            call_count[0] += 1
            if "actuator" in url:
                return _make_response('{"loggers": {}}', 200)
            return _make_response("", 404)

        with patch("spring2shell.audit.log_audit.requests.get", side_effect=get_side):
            result = safe_log_audit("http://t.example")

        assert any("actuator" in ev.lower() or "Accessible" in ev
                   for ev in result.get("evidence", []))
