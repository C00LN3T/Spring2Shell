"""
Unit tests for core/reporter.py:
- build_finding
- evaluate_finding_strictness
- build_siem_schema_report
- write_report / write_txt_report / write_dual_report
- print_summary
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# build_finding
# ---------------------------------------------------------------------------


class TestBuildFinding:
    def test_required_keys_present(self) -> None:
        from spring2shell.core.reporter import build_finding

        f = build_finding("http://t.example", "http://t.example/api", status="confirmed")
        assert f["url"] == "http://t.example"
        assert f["endpoint"] == "http://t.example/api"
        assert f["status"] == "confirmed"
        assert "timestamp" in f

    def test_optional_cve_absent_when_not_given(self) -> None:
        from spring2shell.core.reporter import build_finding

        f = build_finding("http://t.example", "http://t.example/api", status="unverified")
        assert "cve" not in f

    def test_cve_present_when_given(self) -> None:
        from spring2shell.core.reporter import build_finding

        f = build_finding(
            "http://t.example", "http://t.example/api", status="confirmed", cve="CVE-2021-44228"
        )
        assert f["cve"] == "CVE-2021-44228"

    def test_payload_truncated_to_200_chars(self) -> None:
        from spring2shell.core.reporter import build_finding

        long_payload = "A" * 500
        f = build_finding(
            "http://t.example", "http://t.example/api", status="unverified", payload=long_payload
        )
        assert len(f["payload"]) == 200

    def test_extra_fields_merged(self) -> None:
        from spring2shell.core.reporter import build_finding

        f = build_finding(
            "http://t.example",
            "http://t.example/api",
            status="confirmed",
            extra={"custom_key": "custom_value"},
        )
        assert f["custom_key"] == "custom_value"

    def test_framework_field(self) -> None:
        from spring2shell.core.reporter import build_finding

        f = build_finding(
            "http://t.example", "http://t.example/api", status="unverified", framework="React2Shell"
        )
        assert f["framework"] == "React2Shell"


# ---------------------------------------------------------------------------
# evaluate_finding_strictness
# ---------------------------------------------------------------------------


class TestEvaluateFindingStrictness:
    def test_confirmed_status(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness({"status": "confirmed"})
        assert r["status"] == "confirmed"
        assert r["confidence"] == "high"
        assert r["reason_code"] == "RCE_CONFIRMED_REPRODUCIBLE"

    def test_legacy_confirmed(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness({"vulnerable": "Confirmed"})
        assert r["status"] == "confirmed"

    def test_unverified_with_payload(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness(
            {
                "status": "unverified",
                "evidence": "payload accepted",
                "payload": "some_payload",
            }
        )
        assert r["status"] == "unverified"
        assert r["confidence"] == "medium"

    def test_unverified_no_payload(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness({"status": "unverified", "evidence": ""})
        assert r["status"] == "unverified"
        assert r["confidence"] == "low"

    def test_not_vulnerable(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness({"status": "not_vulnerable"})
        assert r["status"] == "not_vulnerable"
        assert r["confidence"] == "low"

    def test_false_status(self) -> None:
        from spring2shell.core.reporter import evaluate_finding_strictness

        r = evaluate_finding_strictness({"vulnerable": False})
        assert r["status"] == "not_vulnerable"


# ---------------------------------------------------------------------------
# build_siem_schema_report
# ---------------------------------------------------------------------------


class TestBuildSiemSchemaReport:
    def test_schema_envelope(self) -> None:
        from spring2shell.core.reporter import build_finding, build_siem_schema_report

        findings = [build_finding("http://t.example", "http://t.example/api", status="confirmed")]
        report = build_siem_schema_report(findings, scan_mode="active")
        assert report["schema_version"] == "1.0"
        assert report["schema_type"] == "react2shell_siem_report"
        assert report["scan_mode"] == "active"
        assert len(report["findings"]) == 1

    def test_empty_findings(self) -> None:
        from spring2shell.core.reporter import build_siem_schema_report

        report = build_siem_schema_report([])
        assert report["findings"] == []

    def test_finding_contains_reason_code(self) -> None:
        from spring2shell.core.reporter import build_finding, build_siem_schema_report

        findings = [build_finding("http://t.example", "http://t.example/api", status="confirmed")]
        report = build_siem_schema_report(findings)
        assert "reason_code" in report["findings"][0]


# ---------------------------------------------------------------------------
# write_report / write_txt_report / write_dual_report
# ---------------------------------------------------------------------------


class TestWriteReport:
    def test_write_report_creates_json(self, tmp_path: Path) -> None:
        from spring2shell.core.reporter import build_finding, write_report

        findings = [build_finding("http://t.example", "http://t.example/api", status="confirmed")]
        path = write_report(findings, tmp_path / "report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert "findings" in data
        assert data["total_findings"] == 1

    def test_write_txt_report_creates_file(self, tmp_path: Path) -> None:
        from spring2shell.core.reporter import build_finding, write_txt_report

        findings = [
            build_finding(
                "http://t.example", "http://t.example/api", status="confirmed", evidence="uid=0"
            )
        ]
        path = write_txt_report(findings, tmp_path / "report.txt")
        assert path.exists()
        content = path.read_text()
        assert "CONFIRMED" in content
        assert "http://t.example" in content

    def test_write_dual_report_returns_both_paths(self, tmp_path: Path) -> None:
        from spring2shell.core.reporter import build_finding, write_dual_report

        findings = [build_finding("http://t.example", "http://t.example/api", status="unverified")]
        json_path, txt_path = write_dual_report(findings, tmp_path / "prefix")
        assert json_path.exists()
        assert txt_path.exists()
        assert json_path.suffix == ".json"
        assert txt_path.suffix == ".txt"

    def test_empty_findings_report(self, tmp_path: Path) -> None:
        from spring2shell.core.reporter import write_report

        path = write_report([], tmp_path / "empty.json")
        data = json.loads(path.read_text())
        assert data["total_findings"] == 0
        assert data["findings"] == []


# ---------------------------------------------------------------------------
# print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_does_not_raise(self, capsys) -> None:
        from spring2shell.core.reporter import build_finding, print_summary

        findings = [
            build_finding("http://t.example", "http://t.example/api", status="confirmed"),
            build_finding("http://t.example", "http://t.example/api2", status="unverified"),
            build_finding("http://t.example", "http://t.example/api3", status="not_vulnerable"),
        ]
        print_summary(findings)
        captured = capsys.readouterr()
        assert "Confirmed" in captured.out
        assert "3" in captured.out
