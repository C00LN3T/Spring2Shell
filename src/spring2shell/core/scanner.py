"""
Core scanner — bulk scan and CVE mass-scan modes for spring2shell.
"""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
from typing import Any

from spring2shell.core.exploiter import direct_exploit
from spring2shell.core.reporter import print_summary, write_report
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
    checkpoint: Any = None,
    use_async: bool = False,
) -> None:
    """Scan all URLs in *targets_file* and write per-target JSON reports.

    Args:
        targets_file:  Path to file with one URL per line.
        output_prefix: Report file prefix (e.g. ``reports/scan``).
        max_workers:   Concurrent worker threads or async tasks.
        checkpoint:    Optional Checkpoint instance.
        use_async:     Use high-concurrency async engine.
    """
    all_targets = _load_targets(targets_file)
    targets = checkpoint.get_remaining(all_targets) if checkpoint else all_targets

    log_event(
        logging.INFO, "bulk-scan start", targets=len(targets), mode="async" if use_async else "sync"
    )
    all_findings: list[dict[str, Any]] = list(checkpoint.get_all_results() if checkpoint else [])

    try:
        from spring2shell.utils.auth import send_webhook
    except ImportError:
        send_webhook = lambda finding: None  # noqa: E731

    if use_async:
        import asyncio

        from spring2shell.core.exploiter import async_direct_exploit
        from spring2shell.utils.async_network import create_async_session

        async def _scan_target(sem: asyncio.Semaphore, target: str, session: Any) -> None:
            async with sem:
                if is_interrupted():
                    return
                try:
                    findings = await async_direct_exploit(target, session=session)
                    all_findings.extend(findings)
                    for f in findings:
                        if f.get("status") == "confirmed":
                            send_webhook(f)
                    if findings:
                        safe_name = target.replace("://", "_").replace("/", "_")
                        write_report(findings, f"{output_prefix}_{safe_name}.json")
                    if checkpoint:
                        checkpoint.save_progress(target, findings)
                except Exception as exc:
                    log_event(logging.WARNING, f"scan error for {target}: {exc}")

        async def _main() -> None:
            sem = asyncio.Semaphore(max_workers)
            session = create_async_session()
            try:
                tasks = [_scan_target(sem, t, session) for t in targets]
                await asyncio.gather(*tasks)
            finally:
                await session.close()

        asyncio.run(_main())
    else:
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


def cve_mass_scan(
    targets_file: str,
    output: str | None = None,
    use_async: bool = False,
    max_workers: int = 5,
) -> None:
    """Run CVE-specific payloads against all URLs in *targets_file*.

    Args:
        targets_file: Path to file with one URL per line.
        output:       Optional output file path for combined results.
        use_async:     Use high-concurrency async engine.
        max_workers:   Concurrency limit for async mode.
    """
    from spring2shell.core.exploiter import async_cve_specific_scan, cve_specific_scan

    targets = _load_targets(targets_file)
    log_event(
        logging.INFO,
        "cve-mass-scan start",
        targets=len(targets),
        mode="async" if use_async else "sync",
    )
    all_findings: list[dict[str, Any]] = []

    if use_async:
        import asyncio

        from spring2shell.utils.async_network import create_async_session

        async def _scan_target(sem: asyncio.Semaphore, target: str, session: Any) -> None:
            async with sem:
                if is_interrupted():
                    return
                try:
                    findings = await async_cve_specific_scan(target, session=session)
                    all_findings.extend(findings)
                    log_event(logging.INFO, f"cve-scan {target}", findings=len(findings))
                except Exception as exc:
                    log_event(logging.WARNING, f"cve-scan error for {target}: {exc}")

        async def _main() -> None:
            sem = asyncio.Semaphore(max_workers)
            session = create_async_session()
            try:
                tasks = [_scan_target(sem, t, session) for t in targets]
                await asyncio.gather(*tasks)
            finally:
                await session.close()

        asyncio.run(_main())
    else:
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
