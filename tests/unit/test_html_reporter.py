"""Unit tests for html_reporter.py — HTML report generation."""

from __future__ import annotations

from spring2shell.core.html_reporter import generate_html_report


def _make_findings():
    from datetime import datetime, timezone

    ts = datetime.now(tz=timezone.utc).isoformat()
    return [
        {
            "url": "http://target.example",
            "endpoint": "http://target.example/api/graphql",
            "status": "confirmed",
            "confidence": "high",
            "cve": "CVE-2025-55182",
            "reason": "RCE_MARKER_REFLECTED",
            "evidence": "Command output reflected: uid=0(root)",
            "payload": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
            "method": "POST",
            "status_code": 200,
            "timestamp": ts,
        },
        {
            "url": "http://target.example",
            "endpoint": "http://target.example/actuator/env",
            "status": "unverified",
            "confidence": "medium",
            "cve": "CVE-2023-46604",
            "reason": "INDICATOR_IN_RESPONSE",
            "evidence": "Found 'activemq' in response",
            "method": "GET",
            "status_code": 200,
            "timestamp": ts,
        },
    ]


class TestHtmlReporter:
    def test_generates_html_file(self, tmp_path):
        """Should create an HTML file at the specified path."""
        output = tmp_path / "report.html"
        findings = _make_findings()
        result = generate_html_report(findings, output)
        assert result == output
        assert output.exists()

    def test_auto_adds_html_extension(self, tmp_path):
        """Should add .html extension if the path has a different suffix."""
        output = tmp_path / "report.json"
        findings = _make_findings()
        result = generate_html_report(findings, output)
        assert result.suffix == ".html"
        assert result.exists()

    def test_html_contains_finding_data(self, tmp_path):
        """Generated HTML should contain key finding data."""
        output = tmp_path / "report.html"
        findings = _make_findings()
        generate_html_report(findings, output)
        content = output.read_text()

        assert "CVE-2025-55182" in content
        assert "CVE-2023-46604" in content
        assert "CONFIRMED" in content
        assert "POTENTIAL" in content
        assert "uid=0(root)" in content

    def test_html_contains_chart_js(self, tmp_path):
        """HTML should include Chart.js for visualisations."""
        output = tmp_path / "report.html"
        generate_html_report(_make_findings(), output)
        content = output.read_text()
        assert "chart.js" in content.lower()

    def test_empty_findings(self, tmp_path):
        """Should handle empty findings list without error."""
        output = tmp_path / "empty.html"
        generate_html_report([], output)
        content = output.read_text()
        assert "No findings detected" in content

    def test_creates_parent_dirs(self, tmp_path):
        """Should create missing parent directories."""
        output = tmp_path / "nested" / "deep" / "report.html"
        generate_html_report(_make_findings(), output)
        assert output.exists()

    def test_confirmed_count_correct(self, tmp_path):
        """Stat counters should reflect actual finding counts."""
        output = tmp_path / "report.html"
        findings = _make_findings()
        generate_html_report(findings, output)
        content = output.read_text()
        # 1 confirmed, 1 unverified in our fixture
        assert ">1<" in content  # stat-number cells

    def test_remediation_included(self, tmp_path):
        """Known CVEs should have remediation advice in the report."""
        output = tmp_path / "report.html"
        generate_html_report(_make_findings(), output)
        content = output.read_text()
        assert "Upgrade Spring Framework" in content

    def test_bootstrap_included(self, tmp_path):
        """HTML should load Bootstrap 5."""
        output = tmp_path / "report.html"
        generate_html_report(_make_findings(), output)
        content = output.read_text()
        assert "bootstrap" in content.lower()
