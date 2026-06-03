"""
Command-line interface for spring2shell.

Entry point: ``spring2shell`` (after pip install) or ``python -m spring2shell``.

Usage examples:
  spring2shell --help
  spring2shell safe-audit https://target.example
  spring2shell direct https://target.example --test-all
  spring2shell scan targets.txt reports/prefix
  spring2shell cve-scan targets.txt -o cve_results.json
  spring2shell ssrf-scan https://target.example
  spring2shell ssti-scan https://target.example
  spring2shell --auth-bearer TOKEN --proxy http://127.0.0.1:8080 direct https://t.example
  spring2shell --rate 50 --audit-log audit.jsonl scan targets.txt results/run1
"""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from spring2shell import __version__
from spring2shell.utils.network import configure_runtime
from spring2shell.utils.signals import register as register_signals

# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _cmd_safe_audit(args: argparse.Namespace) -> int:
    from spring2shell.audit.safe_audit import run_safe_audit
    from spring2shell.core.html_reporter import generate_html_report
    from spring2shell.core.reporter import print_summary, write_report

    findings = run_safe_audit(args.target)
    print_summary(findings)
    if args.output:
        path = write_report(findings, args.output)
        print(f"[+] Report saved: {path}")
        if getattr(args, "html_report", False):
            html_path = generate_html_report(findings, path.with_suffix(".html"))
            print(f"[+] HTML report: {html_path}")
    return 0 if not any(f["status"] == "confirmed" for f in findings) else 1


def _cmd_log_audit(args: argparse.Namespace) -> int:
    from spring2shell.audit.log_audit import run_log_audit
    from spring2shell.core.reporter import print_summary, write_report

    findings = run_log_audit(args.target)
    print_summary(findings)
    if args.output:
        path = write_report(findings, args.output)
        print(f"[+] Report saved: {path}")
    return 0


def _cmd_direct(args: argparse.Namespace) -> int:
    from spring2shell.core.exploiter import direct_exploit
    from spring2shell.core.reporter import print_summary
    from spring2shell.utils.auth import send_webhook

    findings = direct_exploit(
        args.target,
        endpoint=getattr(args, "endpoint", None),
        command=getattr(args, "command", "whoami"),
        test_all=getattr(args, "test_all", False),
        aggressive=getattr(args, "aggressive", False),
    )
    print_summary(findings)

    # Webhook for confirmed findings
    for f in findings:
        if f.get("status") == "confirmed":
            send_webhook(f)

    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from spring2shell.core.checkpoint import Checkpoint
    from spring2shell.core.scanner import bulk_scan

    cp = Checkpoint(args.output_prefix) if getattr(args, "resume", False) else None

    bulk_scan(
        args.targets_file,
        args.output_prefix,
        max_workers=getattr(args, "threads", 5),
        checkpoint=cp,
        use_async=getattr(args, "async_mode", False),
    )

    combined = Path(f"{args.output_prefix}_combined.json")
    if combined.exists():
        try:
            findings = json.loads(combined.read_text()).get("findings", [])
        except Exception:
            findings = []

        formats = [f.strip() for f in getattr(args, "format", "json,txt").split(",")]
        if getattr(args, "html_report", False) and "html" not in formats:
            formats.append("html")

        from spring2shell.core.reporter import write_formatted_reports

        written = write_formatted_reports(
            findings, f"{args.output_prefix}_combined", formats=formats
        )
        for fmt, path in written.items():
            print(f"[+] {fmt.upper()} report written: {path}")

    if getattr(args, "encrypt_reports", False):
        from spring2shell.core.crypto import encrypt_report

        if combined.exists():
            enc_path = encrypt_report(combined)
            print(f"[+] Report encrypted: {enc_path}")
    return 0


def _cmd_cve_scan(args: argparse.Namespace) -> int:
    from spring2shell.core.scanner import cve_mass_scan

    cve_mass_scan(
        args.targets_file,
        output=getattr(args, "output", None),
        use_async=getattr(args, "async_mode", False),
        max_workers=getattr(args, "threads", 5),
    )
    return 0


def _cmd_profile_waf(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from spring2shell.core.waf_profiler import print_waf_profile, profile_waf

    report = profile_waf(args.target)
    print_waf_profile(report)

    if args.output:
        path = Path(args.output)
        path.write_text(json.dumps(report, indent=4))
        print(f"[+] Diagnostic profile saved: {path}")

    return 0


def _cmd_ssrf_scan(args: argparse.Namespace) -> int:
    from spring2shell.core.html_reporter import generate_html_report
    from spring2shell.core.reporter import print_summary, write_report
    from spring2shell.core.ssrf import ssrf_scan

    findings = ssrf_scan(args.target)
    print_summary(findings)
    if args.output:
        path = write_report(findings, args.output)
        print(f"[+] SSRF report saved: {path}")
        if getattr(args, "html_report", False):
            html_path = generate_html_report(findings, path.with_suffix(".html"))
            print(f"[+] HTML report: {html_path}")
    return 0


def _cmd_ssti_scan(args: argparse.Namespace) -> int:
    from spring2shell.core.html_reporter import generate_html_report
    from spring2shell.core.reporter import print_summary, write_report
    from spring2shell.core.ssti import ssti_scan

    findings = ssti_scan(args.target)
    print_summary(findings)
    if args.output:
        path = write_report(findings, args.output)
        print(f"[+] SSTI report saved: {path}")
        if getattr(args, "html_report", False):
            html_path = generate_html_report(findings, path.with_suffix(".html"))
            print(f"[+] HTML report: {html_path}")
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    from spring2shell.core.crypto import decrypt_report, encrypt_report

    if args.action == "encrypt":
        out = encrypt_report(args.file, remove_original=getattr(args, "remove_original", False))
        print(f"[+] Encrypted: {out}")
    else:
        out = decrypt_report(args.file)
        print(f"[+] Decrypted: {out}")
    return 0


def _cmd_nuclei_export(args: argparse.Namespace) -> int:
    """Export scan findings as Nuclei v3 YAML templates."""
    import json
    from pathlib import Path

    from spring2shell.utils.nuclei_export import export_templates

    report_path = Path(args.report_file)
    if not report_path.exists():
        print(f"[!] Report file not found: {report_path}")
        return 1
    try:
        data = json.loads(report_path.read_text())
        findings = data.get("findings", data) if isinstance(data, dict) else data
    except Exception as exc:
        print(f"[!] Could not parse report: {exc}")
        return 1
    created = export_templates(findings, args.output_dir)
    print(f"[+] {len(created)} Nuclei templates written to {args.output_dir}")
    for p in created[:10]:
        print(f"    {p}")
    if len(created) > 10:
        print(f"    ... and {len(created) - 10} more")
    return 0


def _cmd_defectdojo_upload(args: argparse.Namespace) -> int:
    """Upload scan findings to DefectDojo."""
    import os
    from pathlib import Path

    from spring2shell.utils.defectdojo import upload_to_defectdojo

    report_path = Path(args.report_file)
    if not report_path.exists():
        print(f"[!] Report file not found: {report_path}")
        return 1

    url = args.url or os.environ.get("DEFECTDOJO_URL")
    api_key = args.api_key or os.environ.get("DEFECTDOJO_API_KEY")
    env_id = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID")
    engagement_id = args.engagement_id or (int(env_id) if env_id else None)

    if not url or not api_key or not engagement_id:
        print("[!] Missing required DefectDojo parameters (url, api_key, engagement_id).")
        print(
            "    Pass them as CLI arguments or set environment variables: DEFECTDOJO_URL, DEFECTDOJO_API_KEY, DEFECTDOJO_ENGAGEMENT_ID"
        )
        return 1

    success = upload_to_defectdojo(
        report_path=report_path,
        defectdojo_url=url,
        api_key=api_key,
        engagement_id=engagement_id,
        lead_id=args.lead_id,
        environment=args.environment,
    )
    if success:
        return 0
    return 1


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify a potential RCE: echo-marker test + optional blind (time-delay + DNS)."""
    from spring2shell.core.verifier import blind_rce_test, check_real_rce

    endpoint = getattr(args, "endpoint", None) or (args.target.rstrip("/") + "/api/graphql")
    method = getattr(args, "method", "POST")

    print(f"[+] Verifying RCE on {args.target}")
    print(f"[+] Endpoint: {endpoint}")

    is_real = check_real_rce(args.target, endpoint, method)
    if not is_real:
        print("[*] Echo-marker test negative — running blind RCE check...")
        blind_rce_test(args.target, endpoint, method)
    return 0 if not is_real else 1


def _cmd_exploit(args: argparse.Namespace) -> int:
    """Load a JSON report and drive interactive exploitation."""
    from spring2shell.core.report_loader import load_report_and_exploit

    load_report_and_exploit(args.report_file)
    return 0


def _cmd_menu(args: argparse.Namespace) -> int:
    """Launch the 13-item interactive TUI menu."""
    _interactive_menu()
    return 0


def _interactive_menu() -> None:
    """13-item interactive TUI — identical in spirit to the original monolith menu."""
    import sys

    from spring2shell.audit.log_audit import safe_log_audit
    from spring2shell.audit.safe_audit import safe_full_audit
    from spring2shell.core.exploiter import (
        cve_specific_scan,
        direct_exploit,
        exploit_vulnerability,
        find_working_endpoint,
    )
    from spring2shell.core.report_loader import load_report_and_exploit
    from spring2shell.core.reporter import print_summary
    from spring2shell.core.verifier import blind_rce_test, check_real_rce

    print("\n" + "=" * 70)
    print("ULTIMATE REACT4SHELL / REACT2SHELL FRAMEWORK")
    print("CVE-2025-55182, CVE-2025-66478, Log4Shell, Spring4Shell, Text4Shell")
    print("=" * 70)
    print("\nOptions:")
    print("  1.  Scan new targets (bulk)")
    print("  2.  Load and exploit from existing report")
    print("  3.  Direct exploitation (manual target)")
    print("  4.  Verify RCE (echo-marker + blind test)")
    print("  5.  Aggressive exploitation (WAF bypass)")
    print("  6.  CVE-specific scan")
    print("  7.  Find working endpoints (quick probe)")
    print("  8.  Safe full audit (encoding + log + deps + misconfig)")
    print("  9.  Log4Shell risk audit")
    print("  10. React2Shell probe")
    print("  11. SSRF scan")
    print("  12. SSTI scan")
    print("  13. Exit")

    def _input(prompt: str) -> str:
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Interrupted")
            sys.exit(0)

    while True:
        choice = _input("\nSelect option > ")

        if choice == "1":
            targets_file = _input("Enter path to targets file: ")
            output_prefix = _input("Enter output prefix (e.g. reports/run1): ")
            threads_s = _input("Threads (Enter = auto): ")
            threads = int(threads_s) if threads_s.isdigit() and int(threads_s) > 0 else 5
            if targets_file and output_prefix:
                from spring2shell.core.scanner import bulk_scan

                bulk_scan(targets_file, output_prefix, threads=threads)
            else:
                print("[!] Targets file and output prefix required")

        elif choice == "2":
            report_file = _input("Enter path to report JSON file: ")
            if report_file:
                load_report_and_exploit(report_file)
            else:
                print("[!] Report file path required")

        elif choice == "3":
            target = _input("Enter target URL: ")
            endpoint = _input("Enter endpoint (Enter = auto-detect): ")
            cmd = _input("Command (Enter = id): ") or "id"
            if not target:
                print("[!] Target URL required")
                continue
            if not endpoint:
                print("[+] Auto-detecting working endpoints...")
                working = find_working_endpoint(target)
                if working:
                    for i, ep in enumerate(working, 1):
                        print(f"  {i}. {ep['url']} ({ep['method']})")
                    sel = _input("Select [number/all]: ").lower()
                    if sel == "all":
                        for ep in working:
                            print_summary(
                                exploit_vulnerability(
                                    target, ep["url"], method=ep["method"], command=cmd
                                )
                            )
                    elif sel.isdigit():
                        ep = working[int(sel) - 1]
                        print_summary(
                            exploit_vulnerability(
                                target, ep["url"], method=ep["method"], command=cmd
                            )
                        )
                else:
                    print("[-] No endpoints found — running direct_exploit...")
                    print_summary(direct_exploit(target, command=cmd))
            else:
                print_summary(exploit_vulnerability(target, endpoint, command=cmd))

        elif choice == "4":
            target = _input("Enter target URL: ")
            endpoint = _input("Enter endpoint (Enter = auto): ") or (
                target.rstrip("/") + "/api/graphql"
            )
            if target:
                if not check_real_rce(target, endpoint):
                    blind_rce_test(target, endpoint)
            else:
                print("[!] Target URL required")

        elif choice == "5":
            target = _input("Enter target URL: ")
            endpoint = _input("Enter endpoint: ")
            cmd = _input("Command (Enter = id): ") or "id"
            if target and endpoint:
                print_summary(exploit_vulnerability(target, endpoint, command=cmd, aggressive=True))
            else:
                print("[!] Target URL and endpoint required")

        elif choice == "6":
            target = _input("Enter target URL: ")
            if target:
                results = cve_specific_scan(target)
                print_summary(results)
                if results:
                    exploit = _input("Exploit found vulnerabilities? (yes/no): ")
                    if exploit in ("yes", "y"):
                        for r in results:
                            cmd = (
                                _input(f"Command for {r.get('cve', 'N/A')} (Enter = whoami): ")
                                or "whoami"
                            )
                            print_summary(
                                exploit_vulnerability(r["url"], r["endpoint"], command=cmd)
                            )
            else:
                print("[!] Target URL required")

        elif choice == "7":
            target = _input("Enter target URL: ")
            if target:
                found = find_working_endpoint(target)
                if found:
                    for ep in found:
                        print(f"  [{ep['method']}] {ep['url']} (HTTP {ep['status']})")
                else:
                    print("[-] No working endpoints found")
            else:
                print("[!] Target URL required")

        elif choice == "8":
            target = _input("Enter target URL: ")
            if target:
                from spring2shell.core.reporter import write_dual_report

                results = safe_full_audit(target)
                risk = results.get("strict_summary", {}).get("overall_risk", "unknown")
                print(f"[+] Overall risk: {risk.upper()}")
                out = _input("Save report? Enter prefix (Enter = skip): ")
                if out:
                    j, t = write_dual_report(
                        results.get("log_findings", []) + results.get("encoding", []),
                        out,
                    )
                    print(f"[+] JSON: {j}  TXT: {t}")
            else:
                print("[!] Target URL required")

        elif choice == "9":
            target = _input("Enter target URL: ")
            if target:
                findings = safe_log_audit(target)
                print(f"[+] Risk: {findings.get('risk', 'unknown').upper()}")
                for ev in findings.get("evidence", []):
                    print(f"  {ev}")
            else:
                print("[!] Target URL required")

        elif choice == "10":
            target = _input("Enter target URL: ")
            if target:
                from spring2shell.react2shell.scanner import scan_react2shell

                print_summary(scan_react2shell(target))
            else:
                print("[!] Target URL required")

        elif choice == "11":
            target = _input("Enter target URL: ")
            if target:
                from spring2shell.core.ssrf import ssrf_scan

                print_summary(ssrf_scan(target))
            else:
                print("[!] Target URL required")

        elif choice == "12":
            target = _input("Enter target URL: ")
            if target:
                from spring2shell.core.ssti import ssti_scan

                print_summary(ssti_scan(target))
            else:
                print("[!] Target URL required")

        elif choice == "13":
            print("[+] Exiting...")
            sys.exit(0)

        else:
            print("[!] Invalid option")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spring2shell",
        description=(
            "CVE scanner and exploitation toolkit for Spring/GraphQL/React stacks.\n"
            "For authorized testing only. Ensure you have permission before use."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  spring2shell scan targets.txt reports/run1\n"
            "  spring2shell direct https://t.example --test-all -c whoami\n"
            "  spring2shell --auth-bearer TOKEN --proxy http://127.0.0.1:8080 direct https://t.example\n"
            "  spring2shell --oob-server https://interact.example.com --oob-token TOKEN cve-scan t.txt\n"
            "  spring2shell --rate 50 --audit-log audit.jsonl scan targets.txt results/run1\n"
            "  spring2shell ssrf-scan https://target.example -o ssrf.json --html-report\n"
            "  spring2shell ssti-scan https://target.example -o ssti.json\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # ── Global security flags ────────────────────────────────────────────────
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (not recommended).",
    )
    parser.add_argument(
        "--verbose-errors",
        action="store_true",
        default=False,
        help="Log swallowed network exceptions for diagnostics.",
    )
    parser.add_argument(
        "--profile",
        choices=["default", "aggressive", "safe-audit", "stealth"],
        default="default",
        help="Runtime profile (timeout, retries, delay). Default: default.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print payloads and endpoints that WOULD be sent without making real HTTP requests.",
    )

    # ── Auth flags ───────────────────────────────────────────────────────────
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--auth-bearer",
        metavar="TOKEN",
        help="Bearer token for Authorization header.",
    )
    auth_group.add_argument(
        "--auth-basic",
        metavar="USER:PASS",
        help="HTTP Basic auth credentials (USER:PASS).",
    )
    auth_group.add_argument(
        "--auth-cookie",
        metavar="NAME=VALUE[;NAME2=VALUE2]",
        help="Cookie(s) for authenticated sessions (semicolon-separated).",
    )
    auth_group.add_argument(
        "--auth-header",
        metavar="Header:Value[;Header2:Value2]",
        help="Custom authentication header(s) (semicolon-separated).",
    )

    # ── Network flags ────────────────────────────────────────────────────────
    net_group = parser.add_argument_group("network")
    net_group.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050).",
    )
    net_group.add_argument(
        "--rate",
        type=int,
        default=0,
        metavar="N",
        help="Max requests per second — 0 = unlimited (default: 0).",
    )

    # ── OOB flags ────────────────────────────────────────────────────────────
    oob_group = parser.add_argument_group("OOB (blind RCE)")
    oob_group.add_argument(
        "--oob-server",
        metavar="URL",
        help="Self-hosted Interactsh server URL for blind RCE detection.",
    )
    oob_group.add_argument(
        "--oob-token",
        metavar="TOKEN",
        help="Authentication token for OOB server.",
    )

    # ── Output flags ─────────────────────────────────────────────────────────
    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--audit-log",
        metavar="FILE",
        help="Write JSONL audit trail of all requests to this file.",
    )
    out_group.add_argument(
        "--webhook",
        metavar="URL",
        help="Webhook URL for real-time Confirmed-RCE notifications (Slack/Teams/Telegram).",
    )
    out_group.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Path to YAML config file (default: ./config.yaml if it exists).",
    )

    # ── Sub-commands ─────────────────────────────────────────────────────────
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # safe-audit
    p_safe = sub.add_parser("safe-audit", help="Passive encoding/misconfiguration audit (no RCE).")
    p_safe.add_argument("target", help="Target URL.")
    p_safe.add_argument("-o", "--output", help="Write JSON report to this file.")
    p_safe.add_argument("--html-report", action="store_true", help="Also generate HTML report.")

    # log-audit
    p_log = sub.add_parser("log-audit", help="Passive Log4Shell/Log2Shell risk audit.")
    p_log.add_argument("target", help="Target URL.")
    p_log.add_argument("-o", "--output", help="Write JSON report to this file.")

    # direct
    p_direct = sub.add_parser("direct", help="Direct exploitation of a single target.")
    p_direct.add_argument("target", help="Target URL.")
    p_direct.add_argument("-e", "--endpoint", help="Focus on this specific endpoint path.")
    p_direct.add_argument("-c", "--command", default="whoami", help="Command to execute.")
    p_direct.add_argument("--test-all", action="store_true", help="Test all known endpoints.")
    p_direct.add_argument("--aggressive", action="store_true", help="Enable aggressive WAF bypass.")
    p_direct.add_argument(
        "--no-strict-verify",
        action="store_true",
        help="Disable 2-marker strict verification (faster but more false-positives).",
    )
    p_direct.add_argument(
        "--quick",
        action="store_true",
        help="Test only 6 common endpoints (graphql, api, actuator).",
    )
    p_direct.add_argument(
        "--hybrid", action="store_true", help="Use hybrid CVE+generic payloads simultaneously."
    )
    p_direct.add_argument(
        "--find-endpoints",
        action="store_true",
        help="Auto-detect working endpoints before exploiting.",
    )

    # scan
    p_scan = sub.add_parser("scan", help="Bulk scan from a targets file.")
    p_scan.add_argument("targets_file", help="File with one URL per line.")
    p_scan.add_argument("output_prefix", help="Output file prefix (e.g. reports/scan).")
    p_scan.add_argument(
        "-t", "--threads", type=int, default=5, help="Worker threads or async tasks (default: 5)."
    )
    p_scan.add_argument("--resume", action="store_true", help="Resume from last checkpoint.")
    p_scan.add_argument("--html-report", action="store_true", help="Also generate HTML report.")
    p_scan.add_argument("--encrypt-reports", action="store_true", help="Encrypt output reports.")
    p_scan.add_argument(
        "--format",
        default="json,txt",
        help="Report formats to generate (comma-separated: json,txt,html,sarif).",
    )
    p_scan.add_argument(
        "--async", dest="async_mode", action="store_true", help="Use high-concurrency async engine."
    )

    # cve-scan
    p_cve = sub.add_parser("cve-scan", help="CVE-focused mass scan.")
    p_cve.add_argument("targets_file", help="File with one URL per line.")
    p_cve.add_argument("-o", "--output", help="Write results to this file.")
    p_cve.add_argument(
        "-t", "--threads", type=int, default=5, help="Worker threads or async tasks (default: 5)."
    )
    p_cve.add_argument(
        "--async", dest="async_mode", action="store_true", help="Use high-concurrency async engine."
    )

    # profile-waf
    p_profile = sub.add_parser(
        "profile-waf",
        help="safely profile a target URL to check which characters/methods trigger WAF blocks.",
    )
    p_profile.add_argument("target", help="Target URL to profile.")
    p_profile.add_argument("-o", "--output", help="Write diagnostic JSON report to this file.")

    # verify
    p_verify = sub.add_parser("verify", help="Verify if a previous RCE finding is real.")
    p_verify.add_argument("target", help="Target base URL.")
    p_verify.add_argument("-e", "--endpoint", help="Endpoint to verify (default: /api/graphql).")
    p_verify.add_argument(
        "-m",
        "--method",
        default="POST",
        choices=["POST", "GET"],
        help="HTTP method (default: POST).",
    )

    # exploit
    p_exploit = sub.add_parser("exploit", help="Load JSON report and exploit interactively.")
    p_exploit.add_argument("report_file", help="Path to JSON scan report.")

    # menu
    sub.add_parser("menu", help="Launch interactive 13-item TUI menu.")

    # ssrf-scan
    p_ssrf = sub.add_parser("ssrf-scan", help="SSRF vulnerability scan.")
    p_ssrf.add_argument("target", help="Target URL.")
    p_ssrf.add_argument("-o", "--output", help="Write JSON report to this file.")
    p_ssrf.add_argument("--html-report", action="store_true", help="Also generate HTML report.")

    # ssti-scan
    p_ssti = sub.add_parser("ssti-scan", help="SSTI (template injection) scan.")
    p_ssti.add_argument("target", help="Target URL.")
    p_ssti.add_argument("-o", "--output", help="Write JSON report to this file.")
    p_ssti.add_argument("--html-report", action="store_true", help="Also generate HTML report.")

    # encrypt / decrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt or decrypt a report file.")
    p_enc.add_argument("action", choices=["encrypt", "decrypt"], help="encrypt or decrypt.")
    p_enc.add_argument("file", help="Report file to process.")
    p_enc.add_argument(
        "--remove-original", action="store_true", help="Delete plaintext file after encryption."
    )

    # nuclei-export
    p_nuclei = sub.add_parser("nuclei-export", help="Export findings as Nuclei v3 YAML templates.")
    p_nuclei.add_argument("report_file", help="JSON report file to export from.")
    p_nuclei.add_argument("output_dir", help="Directory to write Nuclei templates into.")

    # defectdojo-upload
    p_dojo = sub.add_parser("defectdojo-upload", help="Upload JSON report to DefectDojo.")
    p_dojo.add_argument("report_file", help="Path to JSON scan report.")
    p_dojo.add_argument("--url", help="DefectDojo URL (or DEFECTDOJO_URL env var).")
    p_dojo.add_argument("--api-key", help="API Key (or DEFECTDOJO_API_KEY env var).")
    p_dojo.add_argument(
        "--engagement-id", type=int, help="Engagement ID (or DEFECTDOJO_ENGAGEMENT_ID env var)."
    )
    p_dojo.add_argument("--lead-id", type=int, default=1, help="Lead User ID (default: 1).")
    p_dojo.add_argument(
        "--environment", default="Development", help="Environment (default: Development)."
    )

    return parser


_COMMAND_MAP = {
    "safe-audit": _cmd_safe_audit,
    "log-audit": _cmd_log_audit,
    "direct": _cmd_direct,
    "scan": _cmd_scan,
    "cve-scan": _cmd_cve_scan,
    "ssrf-scan": _cmd_ssrf_scan,
    "ssti-scan": _cmd_ssti_scan,
    "encrypt": _cmd_encrypt,
    "verify": _cmd_verify,
    "exploit": _cmd_exploit,
    "menu": _cmd_menu,
    "nuclei-export": _cmd_nuclei_export,
    "defectdojo-upload": _cmd_defectdojo_upload,
    "profile-waf": _cmd_profile_waf,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> NoReturn:
    """Parse arguments, configure runtime, and dispatch to the appropriate handler."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load config file (CLI args take priority)
    _apply_config(args)

    # Apply global runtime settings before any sub-command runs
    configure_runtime(insecure=args.insecure, verbose_errors=args.verbose_errors)
    register_signals()

    # Configure optional subsystems
    _configure_subsystems(args)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


def _apply_config(args: argparse.Namespace) -> None:
    """Load YAML config and merge into args (CLI wins)."""
    from pathlib import Path

    from spring2shell.utils.network import load_config

    config_path = getattr(args, "config", None)
    if not config_path:
        # Auto-detect default config file
        for candidate in ["config.yaml", "config.yml"]:
            if Path(candidate).exists():
                config_path = candidate
                break

    if not config_path:
        return

    config = load_config(config_path)
    _mapping = {
        "proxy": "proxy",
        "oob_server": "oob_server",
        "oob_token": "oob_token",
        "webhook": "webhook",
        "rate": "rate",
        "audit_log": "audit_log",
        "insecure": "insecure",
    }
    for cfg_key, arg_key in _mapping.items():
        if cfg_key in config and getattr(args, arg_key, None) in (None, False, 0):
            setattr(args, arg_key, config[cfg_key])


def _configure_subsystems(args: argparse.Namespace) -> None:
    """Configure auth, proxy, rate limiter, audit logger, OOB, webhook."""
    try:
        from spring2shell.utils.auth import (
            configure_audit,
            configure_auth,
            configure_proxy,
            configure_rate,
            configure_webhook,
        )

        configure_auth(args)
        configure_proxy(args)
        configure_rate(args)
        configure_audit(args)
        configure_webhook(args)
    except ImportError:
        pass

    try:
        from spring2shell.utils.oob import configure_oob

        configure_oob(args)
    except ImportError:
        pass

    # Dry-run mode must be configured last (it overrides session creation)
    if getattr(args, "dry_run", False):
        try:
            from spring2shell.utils.dry_run import enable_dry_run

            enable_dry_run()
            print("[DRY-RUN] Mode enabled — no real HTTP requests will be sent.")
        except ImportError:
            pass


if __name__ == "__main__":
    main()
