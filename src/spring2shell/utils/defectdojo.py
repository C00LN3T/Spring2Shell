"""
DefectDojo API integration for spring2shell.
"""

from __future__ import annotations

import logging
from pathlib import Path

import requests

from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify


def upload_to_defectdojo(
    report_path: str | Path,
    defectdojo_url: str,
    api_key: str,
    engagement_id: int,
    lead_id: int = 1,
    environment: str = "Development",
) -> bool:
    """Upload a spring2shell JSON report to DefectDojo API.

    Args:
        report_path:    Path to the findings JSON report file.
        defectdojo_url: Base URL of DefectDojo (e.g. ``"https://dojo.example.com"``).
        api_key:        API Key / Token.
        engagement_id:  Target engagement ID.
        lead_id:        User ID of the assessment lead (default: 1).
        environment:    DefectDojo environment name (default: "Development").

    Returns:
        True if the upload succeeded, False otherwise.
    """
    path = Path(report_path)
    if not path.exists():
        log_event(logging.ERROR, f"Report file not found: {path}")
        return False

    url = f"{defectdojo_url.rstrip('/')}/api/v2/import-scan/"
    headers = {
        "Authorization": f"Token {api_key}",
    }

    # DefectDojo generic JSON import parameters
    data = {
        "scan_type": "Generic Findings Import",
        "engagement": engagement_id,
        "lead": lead_id,
        "environment": environment,
        "active": "true",
        "verified": "true",
    }

    try:
        with path.open("rb") as f:
            files = {
                "file": (path.name, f, "application/json"),
            }
            resp = requests.post(
                url,
                headers=headers,
                data=data,
                files=files,
                timeout=20,
                verify=ssl_verify(),
            )
            if resp.status_code in (200, 201):
                log_event(
                    logging.INFO,
                    f"Successfully uploaded report to DefectDojo. Engagement ID: {engagement_id}",
                )
                return True
            else:
                log_event(
                    logging.ERROR,
                    f"DefectDojo upload failed with status {resp.status_code}: {resp.text}",
                )
    except Exception as exc:
        log_swallowed_exception("DefectDojo upload exception", exc)

    return False
