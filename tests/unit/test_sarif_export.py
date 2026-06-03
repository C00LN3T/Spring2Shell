"""
Unit tests for sarif_export.py — SARIF standard export format.
"""

from __future__ import annotations

import json

from spring2shell.utils.sarif_export import export_to_sarif


def test_export_to_sarif(tmp_path):
    output_file = tmp_path / "report.sarif.json"
    findings = [
        {
            "url": "http://example.com",
            "endpoint": "http://example.com/api",
            "status": "confirmed",
            "confidence": "high",
            "cve": "CVE-2025-55182",
            "reason": "RCE_MARKER_REFLECTED",
            "evidence": "Reflected marker",
            "method": "POST",
            "status_code": 200,
        },
        {
            "url": "http://example.com",
            "endpoint": "http://example.com/actuator",
            "status": "unverified",
            "confidence": "medium",
            "reason": "INDICATOR_IN_RESPONSE",
            "evidence": "Spring indicator found",
            "method": "GET",
            "status_code": 200,
        },
    ]

    result_path = export_to_sarif(findings, output_file)
    assert result_path == output_file
    assert output_file.exists()

    # Parse and verify SARIF schema structure
    data = json.loads(output_file.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "spring2shell"
    assert len(run["results"]) == 2

    # Check level mapped correctly
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"
