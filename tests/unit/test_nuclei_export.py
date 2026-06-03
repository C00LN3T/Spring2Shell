"""Unit tests for nuclei_export.py — B3: Nuclei template generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from spring2shell.utils.nuclei_export import (
    _build_template_id,
    _map_severity,
    _sanitize_id,
    export_templates,
    generate_template,
)


def _make_finding(**kwargs):
    defaults = {
        "url": "http://target.example",
        "endpoint": "http://target.example/api/graphql",
        "status": "confirmed",
        "confidence": "high",
        "cve": "CVE-2025-55182",
        "reason": "RCE_MARKER_REFLECTED",
        "evidence": "Command output uid=0(root) reflected in response",
        "payload": '{"query": "{{T(java.lang.Runtime).getRuntime().exec(\\"id\\")}}"}',
        "method": "POST",
        "status_code": 200,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
    defaults.update(kwargs)
    return defaults


class TestSanitizeId:
    def test_lowercase(self):
        assert _sanitize_id("CVE-2025-55182") == "cve-2025-55182"

    def test_replaces_special_chars(self):
        result = _sanitize_id("Spring/GraphQL @API")
        assert "/" not in result
        assert "@" not in result
        assert " " not in result

    def test_no_leading_trailing_dashes(self):
        result = _sanitize_id("--test--")
        assert not result.startswith("-")
        assert not result.endswith("-")

    def test_max_length(self):
        long_str = "a" * 200
        assert len(_sanitize_id(long_str)) <= 80

    def test_collapses_multiple_dashes(self):
        result = _sanitize_id("test   path")
        assert "--" not in result


class TestMapSeverity:
    def test_confirmed_is_critical(self):
        assert _map_severity({"status": "confirmed", "confidence": "high"}) == "critical"

    def test_unverified_high_is_high(self):
        assert _map_severity({"status": "unverified", "confidence": "high"}) == "high"

    def test_unverified_medium_is_medium(self):
        assert _map_severity({"status": "unverified", "confidence": "medium"}) == "medium"

    def test_safe_is_info(self):
        assert _map_severity({"status": "not_vulnerable", "confidence": "low"}) == "info"


class TestBuildTemplateId:
    def test_contains_cve(self):
        finding = _make_finding()
        template_id = _build_template_id(finding)
        assert "cve-2025-55182" in template_id

    def test_starts_with_spring2shell(self):
        finding = _make_finding()
        template_id = _build_template_id(finding)
        assert template_id.startswith("spring2shell")

    def test_no_spaces(self):
        finding = _make_finding()
        assert " " not in _build_template_id(finding)


class TestGenerateTemplate:
    def test_valid_yaml_structure(self):
        finding = _make_finding()
        yaml_str = generate_template(finding)
        assert "id:" in yaml_str
        assert "info:" in yaml_str
        assert "http:" in yaml_str
        assert "matchers:" in yaml_str

    def test_contains_cve(self):
        finding = _make_finding()
        yaml_str = generate_template(finding)
        assert "CVE-2025-55182" in yaml_str

    def test_severity_is_critical_for_confirmed(self):
        finding = _make_finding(status="confirmed")
        yaml_str = generate_template(finding)
        assert "severity: critical" in yaml_str

    def test_severity_is_high_for_unverified_high(self):
        finding = _make_finding(status="unverified", confidence="high")
        yaml_str = generate_template(finding)
        assert "severity: high" in yaml_str

    def test_endpoint_in_path(self):
        finding = _make_finding()
        yaml_str = generate_template(finding)
        assert "/api/graphql" in yaml_str

    def test_has_author_field(self):
        yaml_str = generate_template(_make_finding())
        assert "author: spring2shell" in yaml_str

    def test_post_method(self):
        yaml_str = generate_template(_make_finding(method="POST"))
        assert "method: POST" in yaml_str

    def test_get_method(self):
        yaml_str = generate_template(_make_finding(method="GET"))
        assert "method: GET" in yaml_str
        assert "body:" not in yaml_str

    def test_tags_present(self):
        yaml_str = generate_template(_make_finding())
        assert "tags:" in yaml_str
        assert "spring" in yaml_str


class TestExportTemplates:
    def test_creates_yaml_files(self, tmp_path):
        findings = [_make_finding(), _make_finding(cve="CVE-2021-44228")]
        created = export_templates(findings, tmp_path)
        assert len(created) == 2
        for p in created:
            assert Path(p).exists()
            assert Path(p).suffix == ".yaml"

    def test_skips_not_vulnerable(self, tmp_path):
        findings = [
            _make_finding(status="confirmed"),
            _make_finding(status="not_vulnerable"),
        ]
        created = export_templates(findings, tmp_path)
        assert len(created) == 1

    def test_creates_output_dir(self, tmp_path):
        nested = tmp_path / "nested" / "templates"
        findings = [_make_finding()]
        export_templates(findings, nested)
        assert nested.exists()

    def test_handles_duplicate_ids(self, tmp_path):
        """Two findings with same endpoint/CVE should get unique filenames."""
        findings = [_make_finding(), _make_finding()]  # identical
        created = export_templates(findings, tmp_path)
        assert len(created) == 2
        # File paths should be different
        assert created[0] != created[1]

    def test_yaml_content_valid(self, tmp_path):
        findings = [_make_finding()]
        created = export_templates(findings, tmp_path)
        content = Path(created[0]).read_text()
        assert "id:" in content
        assert "severity:" in content
