"""
Core scanner — bulk scan and CVE mass-scan modes for spring2shell.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
from pathlib import Path
from typing import Any

from spring2shell.core.exploiter import direct_exploit
from spring2shell.core.reporter import build_finding, print_summary, write_report
from spring2shell.utils.logging import log_event
from spring2shell.utils.signals import is_interrupted


def _load_targets(targets_file: str) -> list[str]:
    """Read one URL per line from *targets_file*, skipping blanks and comments."""
    path = Path(targets_file)
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def bulk_scan(
    targets_file: str,
    output_prefix: str,
    max_workers: int = 5,
    checkpoint=None,
) -> None:
    """Scan all URLs in *targets_file* and write per-target JSON reports.

    Args:
        targets_file:  Path to file with one URL per line.
        output_prefix: Report file prefix (e.g. ``reports/scan``).
        max_workers:   Concurrent worker threads.
        checkpoint:    Optional :class:`~spring2shell.core.checkpoint.Checkpoint` instance
                       for scan resume support.
    """
    all_targets = _load_targets(targets_file)
    targets = checkpoint.get_remaining(all_targets) if checkpoint else all_targets

    log_event(logging.INFO, "bulk-scan start", targets=len(targets))
    all_findings: list[dict[str, Any]] = list(checkpoint.get_all_results() if checkpoint else [])

    try:
        from spring2shell.utils.auth import send_webhook
    except ImportError:
        send_webhook = lambda f: None  # noqa: E731

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(direct_exploit, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            if is_interrupted():
                break
            target = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)

                # Webhook for confirmed findings
                for f in findings:
                    if f.get("status") == "confirmed":
                        send_webhook(f)

                if findings:
                    safe_name = target.replace("://", "_").replace("/", "_")
                    write_report(findings, f"{output_prefix}_{safe_name}.json")

                # Save checkpoint progress
                if checkpoint:
                    checkpoint.save_progress(target, findings)

            except Exception as exc:
                log_event(logging.WARNING, f"scan error for {target}: {exc}")

    print_summary(all_findings)
    write_report(all_findings, f"{output_prefix}_combined.json")
    log_event(logging.INFO, "bulk-scan complete", total_findings=len(all_findings))

    if checkpoint:
        checkpoint.finalize()


def cve_mass_scan(targets_file: str, output: str | None = None) -> None:
    """Run CVE-specific payloads against all URLs in *targets_file*.

    Args:
        targets_file: Path to file with one URL per line.
        output:       Optional output file path for combined results.
    """
    from spring2shell.core.exploiter import cve_specific_scan

    targets = _load_targets(targets_file)
    log_event(logging.INFO, "cve-mass-scan start", targets=len(targets))
    all_findings: list[dict[str, Any]] = []

    for target in targets:
        if is_interrupted():
            break
        findings = cve_specific_scan(target)
        all_findings.extend(findings)
        log_event(logging.INFO, f"cve-scan {target}", findings=len(findings))

    print_summary(all_findings)
    if output:
        write_report(all_findings, output)
        print(f"[+] CVE scan results saved: {output}")
    log_event(logging.INFO, "cve-mass-scan complete", total=len(all_findings))
