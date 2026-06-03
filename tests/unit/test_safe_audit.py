"""
Unit tests for audit/safe_audit.py:
- _marker_variants
- safe_encoding_audit
- safe_dependency_audit
- safe_misconfig_audit
- safe_full_audit
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests


def _make_response(text: str = "", status: int = 200, headers: dict | None = None) -> MagicMock:
    r = MagicMock(spec=requests.Response)
    r.text = text
    r.status_code = status
    r.headers = headers or {"Content-Type": "application/json"}
    return r


# ---------------------------------------------------------------------------
# _marker_variants
# ---------------------------------------------------------------------------


class TestMarkerVariants:
    def test_returns_five_variants(self) -> None:
        from spring2shell.audit.safe_audit import _marker_variants

        variants = _marker_variants("TEST_MARKER")
        assert len(variants) == 5

    def test_plain_unchanged(self) -> None:
        from spring2shell.audit.safe_audit import _marker_variants

        variants = _marker_variants("HELLO")
        assert variants["plain"] == "HELLO"

    def test_url_encoded(self) -> None:
        import urllib.parse

        from spring2shell.audit.safe_audit import _marker_variants

        variants = _marker_variants("A B+C")
        assert variants["url"] == urllib.parse.quote("A B+C", safe="")

    def test_base64_decodable(self) -> None:
        import base64

        from spring2shell.audit.safe_audit import _marker_variants

        variants = _marker_variants("MARKER")
        decoded = base64.b64decode(variants["base64"]).decode()
        assert decoded == "MARKER"

    def test_unicode_variant_format(self) -> None:
        from spring2shell.audit.safe_audit import _marker_variants

        variants = _marker_variants("AB")
        assert "\\u0041" in variants["unicode"]  # 'A'
        assert "\\u0042" in variants["unicode"]  # 'B'


# ---------------------------------------------------------------------------
# safe_encoding_audit
# ---------------------------------------------------------------------------


class TestSafeEncodingAudit:
    def test_returns_list(self) -> None:
        from spring2shell.audit.safe_audit import safe_encoding_audit

        session = MagicMock()
        session.post.return_value = _make_response("no reflection")
        session.get.return_value = _make_response("no reflection")

        with patch(
            "spring2shell.audit.safe_audit.create_stealth_session", return_value=session
        ), patch("spring2shell.audit.safe_audit.is_interrupted", return_value=False):
            result = safe_encoding_audit("http://t.example", endpoints=["http://t.example/api"])
        assert isinstance(result, list)

    def test_observation_recorded_when_marker_reflected(self) -> None:

        from spring2shell.audit.safe_audit import safe_encoding_audit

        marker_holder = []

        def post_side(url, data=None, headers=None, timeout=None):
            # reflect whatever is in the "probe" field
            import json as _json

            try:
                body = _json.loads(data)
                probe = body.get("probe", "")
            except Exception:
                probe = ""
            if probe:
                marker_holder.append(probe)
                return _make_response(probe)
            return _make_response("no match")

        session = MagicMock()
        session.post.side_effect = post_side
        session.get.return_value = _make_response("no match")

        with patch(
            "spring2shell.audit.safe_audit.create_stealth_session", return_value=session
        ), patch("spring2shell.audit.safe_audit.is_interrupted", return_value=False):
            result = safe_encoding_audit("http://t.example", endpoints=["http://t.example/api"])

        # At least one endpoint result with decoding observations
        assert len(result) >= 1

    def test_no_crash_on_connection_error(self) -> None:
        from spring2shell.audit.safe_audit import safe_encoding_audit

        session = MagicMock()
        session.post.side_effect = ConnectionError("refused")
        session.get.side_effect = ConnectionError("refused")

        with patch(
            "spring2shell.audit.safe_audit.create_stealth_session", return_value=session
        ), patch("spring2shell.audit.safe_audit.is_interrupted", return_value=False):
            result = safe_encoding_audit("http://t.example", endpoints=["http://t.example/api"])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# safe_dependency_audit
# ---------------------------------------------------------------------------


class TestSafeDependencyAudit:
    def test_returns_dict_with_leaks_key(self) -> None:
        from spring2shell.audit.safe_audit import safe_dependency_audit

        session = MagicMock()
        session.get.return_value = _make_response("no spring here")

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_dependency_audit("http://t.example")
        assert "leaks" in result
        assert isinstance(result["leaks"], list)

    def test_detects_spring_boot_indicator(self) -> None:
        from spring2shell.audit.safe_audit import safe_dependency_audit

        session = MagicMock()
        session.get.return_value = _make_response('{"spring-boot": "2.7.0", "log4j": "2.14.1"}')

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_dependency_audit("http://t.example")

        assert len(result["leaks"]) > 0
        found_indicators = [ind for leak in result["leaks"] for ind in leak["indicators"]]
        assert "spring-boot" in found_indicators or "log4j" in found_indicators

    def test_empty_response_produces_no_leaks(self) -> None:
        from spring2shell.audit.safe_audit import safe_dependency_audit

        session = MagicMock()
        session.get.return_value = _make_response("")

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_dependency_audit("http://t.example")
        assert result["leaks"] == []


# ---------------------------------------------------------------------------
# safe_misconfig_audit
# ---------------------------------------------------------------------------


class TestSafeMisconfigAudit:
    def test_detects_missing_security_headers(self) -> None:
        from spring2shell.audit.safe_audit import safe_misconfig_audit

        session = MagicMock()
        # Response without any security headers
        session.get.return_value = _make_response("ok", headers={"Content-Type": "text/html"})

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_misconfig_audit("http://t.example")

        issue_types = [i["type"] for i in result["issues"]]
        assert "missing_security_headers" in issue_types

    def test_detects_exposed_actuator(self) -> None:
        from spring2shell.audit.safe_audit import safe_misconfig_audit


        def get_side(url, *args, **kwargs):
            # root request returns good headers
            if url == "http://t.example":
                return _make_response(
                    "ok",
                    headers={
                        "Content-Type": "text/html",
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "SAMEORIGIN",
                        "Content-Security-Policy": "default-src 'self'",
                    },
                )
            # actuator endpoints return 200
            return _make_response('{"_links": {}}', 200)

        session = MagicMock()
        session.get.side_effect = get_side

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_misconfig_audit("http://t.example")

        issue_types = [i["type"] for i in result["issues"]]
        assert "exposed_management_endpoint" in issue_types

    def test_no_crash_on_timeout(self) -> None:
        from spring2shell.audit.safe_audit import safe_misconfig_audit

        session = MagicMock()
        session.get.side_effect = requests.exceptions.Timeout("timeout")

        with patch("spring2shell.audit.safe_audit.create_stealth_session", return_value=session):
            result = safe_misconfig_audit("http://t.example")
        assert "issues" in result


# ---------------------------------------------------------------------------
# safe_full_audit
# ---------------------------------------------------------------------------


class TestSafeFullAudit:
    def test_returns_overall_risk(self) -> None:
        from spring2shell.audit.safe_audit import safe_full_audit

        mock_encoding = []
        mock_log = {
            "risk": "low",
            "versions_detected": [],
            "evidence": [],
            "checked_paths": [],
            "target": "http://t.example",
        }
        mock_log_findings = []
        mock_deps = {"target": "http://t.example", "leaks": []}
        mock_misconfig = {"target": "http://t.example", "issues": []}

        with patch(
            "spring2shell.audit.safe_audit.safe_encoding_audit", return_value=mock_encoding
        ), patch(
            "spring2shell.audit.log_audit.run_log_audit", return_value=mock_log_findings
        ), patch("spring2shell.audit.log_audit.safe_log_audit", return_value=mock_log), patch(
            "spring2shell.audit.safe_audit.safe_dependency_audit", return_value=mock_deps
        ), patch("spring2shell.audit.safe_audit.safe_misconfig_audit", return_value=mock_misconfig):
            result = safe_full_audit("http://t.example")

        assert "strict_summary" in result
        assert "overall_risk" in result["strict_summary"]
        assert result["strict_summary"]["overall_risk"] == "low"

    def test_high_risk_when_log_risk_high(self) -> None:
        from spring2shell.audit.safe_audit import safe_full_audit

        mock_log = {
            "risk": "high",
            "versions_detected": ["2.14.1"],
            "evidence": ["Vulnerable version found"],
            "checked_paths": [],
            "target": "http://t.example",
        }

        with patch("spring2shell.audit.safe_audit.safe_encoding_audit", return_value=[]), patch(
            "spring2shell.audit.log_audit.run_log_audit", return_value=[]
        ), patch("spring2shell.audit.log_audit.safe_log_audit", return_value=mock_log), patch(
            "spring2shell.audit.safe_audit.safe_dependency_audit",
            return_value={"target": "http://t.example", "leaks": []},
        ), patch(
            "spring2shell.audit.safe_audit.safe_misconfig_audit",
            return_value={"target": "http://t.example", "issues": []},
        ):
            result = safe_full_audit("http://t.example")

        assert result["strict_summary"]["overall_risk"] == "high"

    def test_schema_keys_present(self) -> None:
        from spring2shell.audit.safe_audit import safe_full_audit

        with patch("spring2shell.audit.safe_audit.safe_encoding_audit", return_value=[]), patch(
            "spring2shell.audit.log_audit.run_log_audit", return_value=[]
        ), patch(
            "spring2shell.audit.log_audit.safe_log_audit",
            return_value={
                "risk": "low",
                "versions_detected": [],
                "evidence": [],
                "checked_paths": [],
                "target": "http://t.example",
            },
        ), patch(
            "spring2shell.audit.safe_audit.safe_dependency_audit",
            return_value={"target": "http://t.example", "leaks": []},
        ), patch(
            "spring2shell.audit.safe_audit.safe_misconfig_audit",
            return_value={"target": "http://t.example", "issues": []},
        ):
            result = safe_full_audit("http://t.example")

        for key in (
            "schema_version",
            "schema_type",
            "target",
            "encoding",
            "log_risk",
            "dependency_leakage",
            "misconfiguration",
            "strict_summary",
        ):
            assert key in result


# ---------------------------------------------------------------------------
# run_safe_audit
# ---------------------------------------------------------------------------


class TestRunSafeAudit:
    def test_aggregates_findings_properly(self) -> None:
        from spring2shell.audit.safe_audit import run_safe_audit

        mock_encoding = [
            {
                "endpoint": "http://t.example/api",
                "marker": "SAFE_AUDIT_12345",
                "decoding_observations": [
                    {
                        "method": "POST",
                        "variant": "url",
                        "reflected_plain": True,
                        "reflected_encoded": False,
                    }
                ],
                "status": [],
            }
        ]
        mock_log_findings = [
            {
                "url": "http://t.example",
                "endpoint": "http://t.example",
                "status": "unverified",
                "confidence": "medium",
                "reason": "LOG4J_INDICATOR",
                "evidence": "Log4j version detected",
                "method": "GET",
            }
        ]
        mock_deps = {
            "target": "http://t.example",
            "leaks": [
                {
                    "path": "/actuator/env",
                    "status_code": 200,
                    "indicators": ["spring-boot"],
                }
            ],
        }
        mock_misconfig = {
            "target": "http://t.example",
            "issues": [
                {
                    "type": "missing_security_headers",
                    "missing": ["X-Frame-Options"],
                },
                {
                    "type": "version_disclosure",
                    "header": "X-Powered-By",
                    "value": "Express",
                },
                {
                    "type": "exposed_management_endpoint",
                    "path": "/actuator",
                    "status_code": 200,
                },
            ],
        }

        with patch(
            "spring2shell.audit.safe_audit.safe_encoding_audit", return_value=mock_encoding
        ), patch(
            "spring2shell.audit.log_audit.run_log_audit", return_value=mock_log_findings
        ), patch(
            "spring2shell.audit.safe_audit.safe_dependency_audit", return_value=mock_deps
        ), patch(
            "spring2shell.audit.safe_audit.safe_misconfig_audit", return_value=mock_misconfig
        ):
            findings = run_safe_audit("http://t.example")

        assert isinstance(findings, list)
        # 1 from encoding + 1 from log4j + 1 from dependency + 3 from misconfig = 6 findings
        assert len(findings) == 6

        reasons = [f["reason"] for f in findings]
        assert "DECODING_OBSERVATION" in reasons
        assert "LOG4J_INDICATOR" in reasons
        assert "DEPENDENCY_LEAKAGE" in reasons
        assert "MISSING_SECURITY_HEADERS" in reasons
        assert "VERSION_DISCLOSURE" in reasons
        assert "EXPOSED_MANAGEMENT_ENDPOINT" in reasons

