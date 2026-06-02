"""
Unit tests for defectdojo.py — DefectDojo API upload.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from spring2shell.utils.defectdojo import upload_to_defectdojo


def test_upload_to_defectdojo_success(tmp_path):
    report_file = tmp_path / "findings.json"
    report_file.write_text('{"findings": []}')

    resp = MagicMock()
    resp.status_code = 201
    resp.text = "Import success"

    with patch("requests.post", return_value=resp) as mock_post:
        success = upload_to_defectdojo(
            report_path=report_file,
            defectdojo_url="http://dojo.example",
            api_key="secret-key",
            engagement_id=123,
        )

    assert success is True
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert "Authorization" in kwargs["headers"]
    assert kwargs["headers"]["Authorization"] == "Token secret-key"
    assert kwargs["data"]["engagement"] == 123
    assert kwargs["data"]["scan_type"] == "Generic Findings Import"


def test_upload_to_defectdojo_missing_file():
    success = upload_to_defectdojo(
        report_path="nonexistent_file.json",
        defectdojo_url="http://dojo.example",
        api_key="secret-key",
        engagement_id=123,
    )
    assert success is False


def test_upload_to_defectdojo_error_status(tmp_path):
    report_file = tmp_path / "findings.json"
    report_file.write_text('{"findings": []}')

    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad Request"

    with patch("requests.post", return_value=resp):
        success = upload_to_defectdojo(
            report_path=report_file,
            defectdojo_url="http://dojo.example",
            api_key="secret-key",
            engagement_id=123,
        )

    assert success is False
