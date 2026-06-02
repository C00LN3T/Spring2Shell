"""
JSON/TXT report generation for spring2shell.

Provides:
- build_finding():             construct a normalised finding dict
- evaluate_finding_strictness(): normalise legacy finding to {status, confidence, reason_code}
- build_siem_schema_report():  wrap findings into a SIEM-compatible schema
- write_report():              serialise findings to JSON file
- write_txt_report():          human-readable TXT file
- write_dual_report():         write both JSON + TXT simultaneously
- print_summary():             print a summary to stdout
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Finding constructor
# ---------------------------------------------------------------------------

def build_finding(
    url: str,
    endpoint: str,
    status: str,
    *,
    cve: str | None = None,
    confidence: str = "medium",
    reason: str = "",
    evidence: str = "",
    payload: str = "",
    method: str = "POST",
    status_code: int | None = None,
    framework: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a normalised finding dictionary.

    Args:
        url:         Base target URL.
        endpoint:    Full URL of the probed endpoint.
        status:      One of ``"confirmed"``, ``"unverified"``, ``"not_vulnerable"``.
        cve:         Optional CVE identifier.
        confidence:  ``"high"``, ``"medium"``, or ``"low"``.
        reason:      Short machine-readable reason code.
        evidence:    Human-readable description of observed evidence.
        payload:     Truncated payload used (for reference, max 200 chars).
        method:      HTTP method used.
        status_code: HTTP response status code.
        framework:   Detected framework (e.g. ``"React2Shell"``).
        extra:       Any additional metadata key-value pairs.

    Returns:
        Normalised finding dictionary.
    """
    finding: dict[str, Any] = {
        "url": url,
        "endpoint": endpoint,
        "status": status,
        "confidence": confidence,
        "method": method,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
    if cve:
        finding["cve"] = cve
    if reason:
        finding["reason"] = reason
    if evidence:
        finding["evidence"] = evidence
    if payload:
        finding["payload"] = payload[:200]
    if status_code is not None:
        finding["status_code"] = status_code
    if framework:
        finding["framework"] = framework
    if extra:
        finding.update(extra)
    return finding


# ---------------------------------------------------------------------------
# Strictness evaluator (for legacy findings from check_react4shell)
# ---------------------------------------------------------------------------

def evaluate_finding_strictness(finding: dict[str, Any]) -> dict[str, str]:
    """Normalise a legacy finding dict to a {status, confidence, reason_code} record.

    Handles both new-schema findings (``status`` key) and old-schema findings
    (``vulnerable`` key).

    Args:
        finding: A finding dict (from :func:`build_finding` or the old monolith).

    Returns:
        Dict with keys ``status``, ``confidence``, ``reason_code``.
    """
    status = finding.get("status") or finding.get("vulnerable")
    evidence = (finding.get("evidence") or "").lower()
    payload_used = bool(finding.get("payload") or finding.get("payload_used"))

    if status in ("confirmed", "Confirmed"):
        return {
            "status": "confirmed",
            "confidence": "high",
            "reason_code": "RCE_CONFIRMED_REPRODUCIBLE",
        }
    if status in ("unverified", "Unverified", "Potential"):
        if payload_used and any(k in evidence for k in ("payload", "accepted", "api indicator")):
            return {
                "status": "unverified",
                "confidence": "medium",
                "reason_code": "EVIDENCE_PARTIAL_NEEDS_REPLAY",
            }
        return {
            "status": "unverified",
            "confidence": "low",
            "reason_code": "HEURISTIC_SIGNAL_ONLY",
        }
    return {
        "status": "not_vulnerable",
        "confidence": "low",
        "reason_code": "NO_EVIDENCE",
    }


# ---------------------------------------------------------------------------
# SIEM schema report
# ---------------------------------------------------------------------------

def build_siem_schema_report(
    results: list[dict[str, Any]],
    scan_mode: str = "active",
) -> dict[str, Any]:
    """Wrap a list of findings in a SIEM-compatible schema envelope.

    Args:
        results:   List of raw finding dicts.
        scan_mode: Description of the scan mode (``"active"`` / ``"passive"``).

    Returns:
        Dict with ``schema_version``, ``schema_type``, ``scan_mode``,
        ``generated_at``, and ``findings``.
    """
    findings = []
    for r in results:
        meta = evaluate_finding_strictness(r)
        findings.append({
            "target":       r.get("url"),
            "endpoint":     r.get("endpoint"),
            "timestamp":    r.get("timestamp"),
            "status":       meta["status"],
            "confidence":   meta["confidence"],
            "reason_code":  meta["reason_code"],
            "evidence":     r.get("evidence"),
            "status_code":  r.get("status_code"),
            "method":       r.get("method"),
            "cve":          r.get("cve"),
            "raw":          r,
        })
    return {
        "schema_version": "1.0",
        "schema_type":    "react2shell_siem_report",
        "scan_mode":      scan_mode,
        "generated_at":   datetime.now(tz=timezone.utc).isoformat(),
        "findings":       findings,
    }


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Serialise *findings* to a JSON file at *output_path*.

    Args:
        findings:    List of finding dicts.
        output_path: Destination file path.

    Returns:
        Resolved :class:`~pathlib.Path` of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":   datetime.now(tz=timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings":       findings,
        "siem":           build_siem_schema_report(findings),
    }
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return path


def write_txt_report(
    findings: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Write a human-readable TXT report to *output_path*.

    Args:
        findings:    List of finding dicts.
        output_path: Destination ``.txt`` file path.

    Returns:
        Resolved :class:`~pathlib.Path` of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    confirmed  = [f for f in findings if f.get("status") in ("confirmed",  "Confirmed")]
    unverified = [f for f in findings if f.get("status") in ("unverified", "Unverified", "Potential")]

    lines = [
        "=" * 70,
        "ULTIMATE REACT4SHELL SCAN RESULTS",
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
    ]
    if confirmed:
        lines += ["CONFIRMED VULNERABILITIES FOUND:", "-" * 70]
        for i, f in enumerate(confirmed, 1):
            lines.append(
                f"{i}. {f.get('url')}\n"
                f"   Endpoint: {f.get('endpoint')}\n"
                f"   CVE: {f.get('cve', 'N/A')}\n"
                f"   Evidence: {f.get('evidence', '')}\n"
            )
    if unverified:
        lines += ["UNVERIFIED FINDINGS:", "-" * 70]
        for i, f in enumerate(unverified, 1):
            lines.append(
                f"{i}. {f.get('url')}\n"
                f"   Endpoint: {f.get('endpoint')}\n"
                f"   Evidence: {f.get('evidence', '')}\n"
            )
    lines += [
        "", "=" * 70, "SCAN STATISTICS:",
        f"  Total findings:           {len(findings)}",
        f"  Confirmed vulnerabilities: {len(confirmed)}",
        f"  Unverified findings:       {len(unverified)}",
        f"  Safe:                      {len(findings) - len(confirmed) - len(unverified)}",
    ]
    path.write_text("\n".join(lines))
    return path


def write_dual_report(
    findings: list[dict[str, Any]],
    output_prefix: str | Path,
) -> tuple[Path, Path]:
    """Write both ``.json`` and ``.txt`` reports atomically.

    Args:
        findings:       List of finding dicts.
        output_prefix:  Path prefix (without extension).

    Returns:
        Tuple of (json_path, txt_path).
    """
    prefix = Path(output_prefix)
    json_path = write_report(findings, prefix.with_suffix(".json"))
    txt_path  = write_txt_report(findings, prefix.with_suffix(".txt"))
    return json_path, txt_path


def write_formatted_reports(
    findings: list[dict[str, Any]],
    output_prefix: str | Path,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Write scan reports in requested formats (json, txt, html, sarif).

    Args:
        findings:       List of finding dicts.
        output_prefix:  Path prefix (without extension).
        formats:        List of formats to write (e.g. ['json', 'html']).

    Returns:
        Dict mapping format string to the resolved Path written.
    """
    if formats is None:
        formats = ["json", "txt"]

    prefix = Path(output_prefix)
    written: dict[str, Path] = {}

    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt == "json":
            written["json"] = write_report(findings, prefix.with_suffix(".json"))
        elif fmt == "txt":
            written["txt"] = write_txt_report(findings, prefix.with_suffix(".txt"))
        elif fmt == "html":
            from spring2shell.core.html_reporter import generate_html_report
            written["html"] = generate_html_report(findings, prefix.with_suffix(".html"))
        elif fmt == "sarif":
            from spring2shell.utils.sarif_export import export_to_sarif
            written["sarif"] = export_to_sarif(findings, prefix.with_suffix(".sarif.json"))

    return written



# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

def print_summary(findings: list[dict[str, Any]]) -> None:
    """Print a human-readable summary of findings to stdout."""
    confirmed  = [f for f in findings if f.get("status") in ("confirmed",  "Confirmed")]
    unverified = [f for f in findings if f.get("status") in ("unverified", "Unverified", "Potential")]
    not_vuln   = [f for f in findings if f.get("status") == "not_vulnerable"]

    print(f"\n{'=' * 60}")
    print("  SCAN SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total findings  : {len(findings)}")
    print(f"  Confirmed       : {len(confirmed)}")
    print(f"  Unverified      : {len(unverified)}")
    print(f"  Not Vulnerable  : {len(not_vuln)}")
    print(f"{'=' * 60}\n")

    for f in confirmed:
        cve = f"[{f['cve']}] " if f.get("cve") else ""
        print(f"  [CONFIRMED] {cve}{f.get('endpoint', f.get('url'))}")
        if f.get("evidence"):
            print(f"              {f['evidence']}")
    for f in unverified:
        cve = f"[{f['cve']}] " if f.get("cve") else ""
        print(f"  [UNVERIFIED] {cve}{f.get('endpoint', f.get('url'))}")
        if f.get("evidence"):
            print(f"               {f['evidence']}")
