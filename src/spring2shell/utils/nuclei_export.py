"""
Nuclei YAML template generator for spring2shell findings.

Generates .yaml templates compatible with ProjectDiscovery Nuclei v3.
Each confirmed/unverified finding becomes a re-runnable template.

Usage:
    from spring2shell.utils.nuclei_export import export_templates
    paths = export_templates(findings, 'nuclei_templates/')
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── Severity mapping ─────────────────────────────────────────────────────────


def _map_severity(finding: dict[str, Any]) -> str:
    status = finding.get("status", "")
    confidence = finding.get("confidence", "medium")
    if status == "confirmed":
        return "critical"
    if status == "unverified" and confidence == "high":
        return "high"
    if status == "unverified":
        return "medium"
    return "info"


# ─── CVE metadata ─────────────────────────────────────────────────────────────

_CVE_METADATA: dict[str, dict[str, str]] = {
    "CVE-2025-55182": {
        "name": "Spring Framework SpEL Injection",
        "tags": "spring,spel,rce,java",
        "reference": "https://spring.io/security/cve-2025-55182",
    },
    "CVE-2025-66478": {
        "name": "Spring GraphQL SpEL Injection",
        "tags": "spring,graphql,spel,rce,java",
        "reference": "https://spring.io/security/cve-2025-66478",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell ClassLoader RCE",
        "tags": "spring,rce,classloader,java",
        "reference": "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
    },
    "CVE-2021-44228": {
        "name": "Log4Shell JNDI Injection",
        "tags": "log4j,jndi,rce,java,critical",
        "reference": "https://logging.apache.org/log4j/2.x/security.html",
    },
    "CVE-2022-42889": {
        "name": "Text4Shell Apache Commons Text RCE",
        "tags": "commons-text,rce,java",
        "reference": "https://commons.apache.org/proper/commons-text/security.html",
    },
    "CVE-2023-46604": {
        "name": "Apache ActiveMQ RCE",
        "tags": "activemq,rce,java,critical",
        "reference": "https://activemq.apache.org/security-advisories",
    },
    "CVE-2024-22243": {
        "name": "Spring Framework SSRF via UriComponentsBuilder",
        "tags": "spring,ssrf,java",
        "reference": "https://spring.io/security/cve-2024-22243",
    },
    "CVE-2024-38816": {
        "name": "Spring WebFlux Path Traversal",
        "tags": "spring,webflux,path-traversal,java",
        "reference": "https://spring.io/security/cve-2024-38816",
    },
    "CVE-2024-4577": {
        "name": "PHP CGI Argument Injection",
        "tags": "php,cgi,rce,windows",
        "reference": "https://www.php.net/ChangeLog-8.php",
    },
}

_DEFAULT_META = {
    "name": "Vulnerability Detected by spring2shell",
    "tags": "spring2shell,rce",
    "reference": "https://github.com/projectdiscovery/nuclei-templates",
}


# ─── Template ID sanitisation ─────────────────────────────────────────────────


def _sanitize_id(text: str) -> str:
    """Convert arbitrary text to a valid Nuclei template ID."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\-]", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")[:80]


def _build_template_id(finding: dict[str, Any]) -> str:
    cve = finding.get("cve", "")
    endpoint = finding.get("endpoint", finding.get("url", "unknown"))
    try:
        path = urllib.parse.urlparse(endpoint).path.strip("/").replace("/", "-") or "root"
    except Exception:
        path = "endpoint"
    prefix = f"spring2shell-{cve}" if cve else "spring2shell-finding"
    return _sanitize_id(f"{prefix}-{path}")


# ─── YAML generator ───────────────────────────────────────────────────────────


def generate_template(finding: dict[str, Any]) -> str:
    """Generate a Nuclei v3 YAML template string for a single finding.

    Args:
        finding: Finding dict from :func:`~spring2shell.core.reporter.build_finding`.

    Returns:
        YAML template string.
    """
    cve = finding.get("cve", "")
    meta = _CVE_METADATA.get(cve, _DEFAULT_META)
    severity = _map_severity(finding)
    template_id = _build_template_id(finding)
    method = finding.get("method", "POST").upper()
    endpoint = finding.get("endpoint", finding.get("url", ""))
    payload = finding.get("payload", "")
    evidence = finding.get("evidence", "")
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    # Build matcher words from evidence/indicators
    matcher_words: list[str] = []
    for indicator in ["uid=", "gid=", "root:", "java.lang.", "49", "RCE_"]:
        if indicator in evidence or (payload and indicator in payload):
            matcher_words.append(indicator)
    if not matcher_words:
        matcher_words = ["uid=", "gid=", "root:"]

    # Path from endpoint URL
    try:
        parsed = urllib.parse.urlparse(endpoint)
        ep_path = parsed.path or "/"
        # Nuclei uses {{BaseURL}}/path
        nuclei_path = f"{{{{BaseURL}}}}{ep_path}"
    except Exception:
        nuclei_path = "{{BaseURL}}/"

    # Reference block
    ref_block = f"    - {meta['reference']}" if meta.get("reference") else ""
    cve_block = f"\n    cve-id: {cve}" if cve else ""

    # Build body/params section
    if method == "GET":
        method_section = f"""  - method: GET
    path:
      - '{nuclei_path}'
    matchers:"""
    else:
        # Escape single quotes in payload for YAML
        safe_payload = payload.replace("'", "\\'") if payload else '{"query": "{{7*7}}"}'
        method_section = f"""  - method: POST
    path:
      - '{nuclei_path}'
    headers:
      Content-Type: application/json
    body: '{safe_payload[:300]}'
    matchers:"""

    words_yaml = "\n          - '" + "'\n          - '".join(matcher_words) + "'"

    template = f"""id: {template_id}

info:
  name: "{meta["name"]}" - {cve or "spring2shell"}
  author: spring2shell
  severity: {severity}
  description: |
    {evidence[:300] if evidence else "Potential vulnerability detected by spring2shell scanner."}
  tags: {meta["tags"]}
  reference:{chr(10) + ref_block if ref_block else " []"}
  metadata:
    generated: {generated}
    scanner: spring2shell{cve_block}

http:
{method_section}
      - type: word
        words:{words_yaml}
        condition: or
"""
    return template


def export_templates(
    findings: list[dict[str, Any]],
    output_dir: str | Path,
) -> list[str]:
    """Export all findings as Nuclei YAML templates.

    Args:
        findings:    List of finding dicts.
        output_dir:  Directory to write template files.

    Returns:
        List of created file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    created: list[str] = []

    seen_ids: dict[str, int] = {}

    for finding in findings:
        if finding.get("status") == "not_vulnerable":
            continue

        template_yaml = generate_template(finding)
        template_id = _build_template_id(finding)

        # Handle duplicate IDs
        if template_id in seen_ids:
            seen_ids[template_id] += 1
            filename = f"{template_id}-{seen_ids[template_id]}.yaml"
        else:
            seen_ids[template_id] = 0
            filename = f"{template_id}.yaml"

        filepath = out / filename
        filepath.write_text(template_yaml, encoding="utf-8")
        created.append(str(filepath))

    return created
