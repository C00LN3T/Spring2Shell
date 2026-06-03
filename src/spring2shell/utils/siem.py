"""
SIEM / webhook notification module for spring2shell.

Auto-detects destination format from the webhook URL:
- Slack (hooks.slack.com) → Block Kit with colored attachment
- Discord (discord.com/api/webhooks) → Embed with color coding
- Splunk HEC (contains 'splunk' or '?token=') → Splunk HEC JSON event
- Telegram (api.telegram.org) → Telegram Bot sendMessage
- Generic → Plain JSON payload

Usage:
    from spring2shell.utils.siem import send_siem_event
    send_siem_event(finding)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from spring2shell.utils.logging import log_event, log_swallowed_exception
from spring2shell.utils.network import ssl_verify

# ─── Color constants ──────────────────────────────────────────────────────────

_COLOR_CONFIRMED = 0xFF0000  # red
_COLOR_UNVERIFIED = 0xFFA500  # orange
_COLOR_SAFE = 0x00FF00  # green

_SLACK_COLOR_CONFIRMED = "danger"
_SLACK_COLOR_UNVERIFIED = "warning"
_SLACK_COLOR_SAFE = "good"


def _severity_color(status: str) -> int:
    return {"confirmed": _COLOR_CONFIRMED, "unverified": _COLOR_UNVERIFIED}.get(status, _COLOR_SAFE)


def _slack_color(status: str) -> str:
    return {"confirmed": _SLACK_COLOR_CONFIRMED, "unverified": _SLACK_COLOR_UNVERIFIED}.get(
        status, _SLACK_COLOR_SAFE
    )


# ─── Format builders ─────────────────────────────────────────────────────────


def _build_slack_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Slack Block Kit with colored attachment."""
    status = finding.get("status", "unverified")
    cve = finding.get("cve", "N/A")
    url = finding.get("url", "N/A")
    evidence = finding.get("evidence", "")
    severity = status.upper()

    return {
        "text": f"🚨 spring2shell: *{severity}* RCE — `{url}`",
        "attachments": [
            {
                "color": _slack_color(status),
                "fields": [
                    {"title": "CVE", "value": cve, "short": True},
                    {"title": "Status", "value": severity, "short": True},
                    {"title": "Target", "value": url, "short": False},
                    {"title": "Endpoint", "value": finding.get("endpoint", "N/A"), "short": False},
                    {"title": "Evidence", "value": evidence[:200], "short": False},
                ],
                "footer": "spring2shell",
                "ts": int(time.time()),
            }
        ],
    }


def _build_discord_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Discord embed with color coding."""
    status = finding.get("status", "unverified")
    cve = finding.get("cve", "N/A")
    url = finding.get("url", "N/A")

    return {
        "content": f"🚨 **{status.upper()} RCE** detected by spring2shell",
        "embeds": [
            {
                "title": f"CVE {cve}" if cve != "N/A" else "Vulnerability Detected",
                "description": finding.get("evidence", "")[:400],
                "color": _severity_color(status),
                "fields": [
                    {"name": "Target", "value": f"`{url}`", "inline": True},
                    {
                        "name": "Endpoint",
                        "value": f"`{finding.get('endpoint', 'N/A')}`",
                        "inline": True,
                    },
                    {
                        "name": "Confidence",
                        "value": finding.get("confidence", "N/A"),
                        "inline": True,
                    },
                    {"name": "Method", "value": finding.get("method", "N/A"), "inline": True},
                ],
                "footer": {"text": "spring2shell scanner"},
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }
        ],
    }


def _build_splunk_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Splunk HEC (HTTP Event Collector) format."""
    return {
        "time": time.time(),
        "sourcetype": "spring2shell",
        "source": "spring2shell-scanner",
        "index": "security",
        "event": {
            "severity": "critical" if finding.get("status") == "confirmed" else "high",
            "cve": finding.get("cve", "UNKNOWN"),
            "url": finding.get("url", ""),
            "endpoint": finding.get("endpoint", ""),
            "status": finding.get("status", ""),
            "confidence": finding.get("confidence", ""),
            "method": finding.get("method", ""),
            "evidence": finding.get("evidence", ""),
            "reason": finding.get("reason", ""),
            "scanner": "spring2shell",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
    }


def _build_telegram_payload(finding: dict[str, Any], chat_id: str) -> dict[str, Any]:
    """Telegram Bot sendMessage format."""
    status = finding.get("status", "unverified").upper()
    icon = "🚨" if status == "CONFIRMED" else "⚠️"
    text = (
        f"{icon} *spring2shell* — {status}\n"
        f"CVE: `{finding.get('cve', 'N/A')}`\n"
        f"Target: `{finding.get('url', 'N/A')}`\n"
        f"Evidence: {finding.get('evidence', '')[:150]}"
    )
    return {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}


def _build_generic_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Generic JSON payload for any webhook receiver."""
    return {
        "source": "spring2shell",
        "severity": "critical" if finding.get("status") == "confirmed" else "high",
        "text": f"🚨 Vulnerability detected: {finding.get('url', 'N/A')}",
        "cve": finding.get("cve", "UNKNOWN"),
        "status": finding.get("status", ""),
        "endpoint": finding.get("endpoint", "N/A"),
        "evidence": finding.get("evidence", ""),
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ─── Auto-detection + send ────────────────────────────────────────────────────


def _detect_format(url: str) -> str:
    """Detect webhook format from URL."""
    url_lower = url.lower()
    if "hooks.slack.com" in url_lower:
        return "slack"
    if "discord.com/api/webhooks" in url_lower:
        return "discord"
    if "splunk" in url_lower or "token=" in url_lower:
        return "splunk"
    if "api.telegram.org" in url_lower:
        return "telegram"
    return "generic"


def send_siem_event(
    finding: dict[str, Any],
    webhook_url: str | None = None,
    fmt: str = "auto",
    telegram_chat_id: str = "@spring2shell_alerts",
) -> None:
    """Send a finding as a SIEM event to the configured webhook.

    Args:
        finding:           Finding dict from :func:`~spring2shell.core.reporter.build_finding`.
        webhook_url:       Webhook URL (overrides configured URL).
        fmt:               Format: ``"auto"`` | ``"slack"`` | ``"discord"`` | ``"splunk"``
                           | ``"telegram"`` | ``"generic"``.
        telegram_chat_id:  Telegram chat ID (only used for Telegram format).
    """
    # Get URL from param or global config
    if not webhook_url:
        try:
            from spring2shell.utils.auth import get_webhook_url

            webhook_url = get_webhook_url()
        except ImportError:
            pass
    if not webhook_url:
        return

    # Detect format
    if fmt == "auto":
        fmt = _detect_format(webhook_url)

    # Build payload
    if fmt == "slack":
        payload = _build_slack_payload(finding)
    elif fmt == "discord":
        payload = _build_discord_payload(finding)
    elif fmt == "splunk":
        payload = _build_splunk_payload(finding)
    elif fmt == "telegram":
        payload = _build_telegram_payload(finding, telegram_chat_id)
    else:
        payload = _build_generic_payload(finding)

    # Send
    try:
        resp = requests.post(webhook_url, json=payload, timeout=6, verify=ssl_verify())
        log_event(logging.DEBUG, f"SIEM event sent [{fmt}]: HTTP {resp.status_code}")
    except Exception as exc:
        log_swallowed_exception(f"siem send_event [{fmt}]", exc)
