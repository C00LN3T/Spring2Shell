"""
Burp Suite target importer for spring2shell.

Supports:
- Burp XML export (File → Save items as XML)
- Burp JSON export
- Plain URL list (one per line)

Usage:
    from spring2shell.utils.burp_import import load_targets
    targets = load_targets('burp_export.xml')   # auto-detects format
    targets = load_targets('urls.txt')           # plain text
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from pathlib import Path
from typing import Any

from spring2shell.utils.logging import log_event


def load_targets(path: str | Path) -> list[str]:
    """Auto-detect format and return a list of unique base URLs.

    Args:
        path: Path to a Burp XML export, Burp JSON export, or plain text file.

    Returns:
        Deduplicated list of base URLs (scheme + host + port only).
    """
    content = Path(path).read_text(encoding="utf-8", errors="replace")
    stripped = content.lstrip()

    if stripped.startswith("<"):
        raw = _parse_burp_xml(content)
        fmt = "Burp XML"
    elif stripped.startswith("{") or stripped.startswith("["):
        try:
            import json

            data = json.loads(content)
            raw = _parse_burp_json(data)
            fmt = "Burp JSON"
        except Exception:
            raw = _parse_plain_txt(content)
            fmt = "plain text (JSON parse failed)"
    else:
        raw = _parse_plain_txt(content)
        fmt = "plain text"

    bases = _to_base_urls(raw)
    log_event(logging.INFO, f"Burp import ({fmt}): {len(raw)} URLs → {len(bases)} unique base URLs")
    return bases


def _parse_burp_xml(content: str) -> list[str]:
    """Parse Burp Suite XML export — <items><item><url>…</url></item></items>."""
    urls: list[str] = []
    # Strip CDATA wrappers: <![CDATA[...]]> → content inside
    content = re.sub(r"<!\[CDATA\[(.*?)]]>", r"\1", content, flags=re.DOTALL)
    pattern = re.compile(r"<url>(.*?)</url>", re.DOTALL | re.IGNORECASE)
    for match in pattern.finditer(content):
        url = match.group(1).strip()
        url = url.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if url.startswith(("http://", "https://")):
            urls.append(url)
    return urls


def _parse_burp_json(data: Any) -> list[str]:
    """Parse Burp Suite JSON export formats."""
    urls: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key in ("url", "host", "endpoint", "request"):
                    val = item.get(key, "")
                    if isinstance(val, str) and val.startswith(("http://", "https://")):
                        urls.append(val)
                        break
    elif isinstance(data, dict):
        # Top-level dict: try common keys
        for key in ("items", "requests", "urls", "targets"):
            sub = data.get(key, [])
            if isinstance(sub, list):
                urls.extend(_parse_burp_json(sub))
    return urls


def _parse_plain_txt(content: str) -> list[str]:
    """Parse plain text file — one URL per line, skip blank lines and # comments."""
    urls: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            urls.append(line)
        else:
            # Try adding https://
            candidate = f"https://{line}"
            try:
                parsed = urllib.parse.urlparse(candidate)
                if parsed.hostname:
                    urls.append(candidate)
            except Exception:
                pass
    return urls


def _to_base_urls(raw_urls: list[str]) -> list[str]:
    """Deduplicate by base URL (scheme + host + port only)."""
    seen: set[str] = set()
    result: list[str] = []
    for url in raw_urls:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                log_event(logging.WARNING, f"Skipping non-HTTP URL: {url}")
                continue
            # Build base: scheme://host[:port]
            base = f"{parsed.scheme}://{parsed.hostname}"
            if parsed.port and parsed.port not in (80, 443):
                base += f":{parsed.port}"
            if base not in seen:
                seen.add(base)
                result.append(base)
        except Exception:
            pass
    return result
