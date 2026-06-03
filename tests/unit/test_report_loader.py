"""
Unit tests for core/report_loader.py:
- interactive_exploitation_menu
- exploitation_command_menu
- load_report_and_exploit
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# interactive_exploitation_menu
# ---------------------------------------------------------------------------


class TestInteractiveExploitationMenu:
    def test_returns_none_for_empty_list(self, capsys) -> None:
        from spring2shell.core.report_loader import interactive_exploitation_menu

        result = interactive_exploitation_menu([])
        assert result is None

    def test_returns_none_on_back(self) -> None:
        from spring2shell.core.report_loader import interactive_exploitation_menu

        vulns = [{"url": "http://t.example", "endpoint": "/api", "status": "confirmed"}]
        with patch("builtins.input", side_effect=["back"]):
            result = interactive_exploitation_menu(vulns)
        assert result is None

    def test_returns_selected_vuln_on_valid_number(self) -> None:
        from spring2shell.core.report_loader import interactive_exploitation_menu

        vulns = [
            {"url": "http://t1.example", "endpoint": "/api", "status": "confirmed"},
            {"url": "http://t2.example", "endpoint": "/graphql", "status": "unverified"},
        ]
        with patch("builtins.input", side_effect=["2"]):
            result = interactive_exploitation_menu(vulns)
        assert result is not None
        assert result["url"] == "http://t2.example"

    def test_handles_invalid_number_then_valid(self) -> None:
        from spring2shell.core.report_loader import interactive_exploitation_menu

        vulns = [{"url": "http://t.example", "endpoint": "/api", "status": "confirmed"}]
        with patch("builtins.input", side_effect=["99", "1"]):
            result = interactive_exploitation_menu(vulns)
        assert result is not None

    def test_exit_raises_system_exit(self) -> None:
        from spring2shell.core.report_loader import interactive_exploitation_menu

        vulns = [{"url": "http://t.example", "endpoint": "/api", "status": "confirmed"}]
        with patch("builtins.input", return_value="exit"), pytest.raises(SystemExit):
            interactive_exploitation_menu(vulns)


# ---------------------------------------------------------------------------
# exploitation_command_menu
# ---------------------------------------------------------------------------


class TestExploitationCommandMenu:
    def test_returns_preset_by_number(self) -> None:
        from spring2shell.core.report_loader import _PRESET_COMMANDS, exploitation_command_menu

        with patch("builtins.input", return_value="1"):
            result = exploitation_command_menu()
        assert result == _PRESET_COMMANDS[0]

    def test_returns_custom_string(self) -> None:
        from spring2shell.core.report_loader import exploitation_command_menu

        with patch("builtins.input", return_value="cat /etc/shadow"):
            result = exploitation_command_menu()
        assert result == "cat /etc/shadow"

    def test_back_returns_back(self) -> None:
        from spring2shell.core.report_loader import exploitation_command_menu

        with patch("builtins.input", return_value="back"):
            result = exploitation_command_menu()
        assert result == "back"

    def test_exit_returns_exit(self) -> None:
        from spring2shell.core.report_loader import exploitation_command_menu

        with patch("builtins.input", return_value="exit"):
            result = exploitation_command_menu()
        assert result == "exit"


# ---------------------------------------------------------------------------
# load_report_and_exploit
# ---------------------------------------------------------------------------


class TestLoadReportAndExploit:
    def _make_report_file(self, tmp_path: Path, findings: list) -> Path:
        data = {"findings": findings, "total_findings": len(findings)}
        p = tmp_path / "report.json"
        p.write_text(json.dumps(data))
        return p

    def test_missing_file_prints_error(self, capsys) -> None:
        from spring2shell.core.report_loader import load_report_and_exploit

        load_report_and_exploit("/nonexistent/report.json")
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "error" in captured.out.lower()

    def test_invalid_json_prints_error(self, tmp_path: Path, capsys) -> None:
        from spring2shell.core.report_loader import load_report_and_exploit

        bad = tmp_path / "bad.json"
        bad.write_text("{ invalid json {{")
        load_report_and_exploit(str(bad))
        captured = capsys.readouterr()
        assert "invalid" in captured.out.lower() or "error" in captured.out.lower()

    def test_no_vulnerabilities_prints_message(self, tmp_path: Path, capsys) -> None:
        from spring2shell.core.report_loader import load_report_and_exploit

        report = self._make_report_file(
            tmp_path, [{"url": "http://t.example", "endpoint": "/api", "status": "not_vulnerable"}]
        )
        load_report_and_exploit(str(report))
        captured = capsys.readouterr()
        assert "no vulnerabilities" in captured.out.lower()

    def test_user_back_exits_loop(self, tmp_path: Path) -> None:
        from spring2shell.core.report_loader import load_report_and_exploit

        report = self._make_report_file(
            tmp_path,
            [
                {
                    "url": "http://t.example",
                    "endpoint": "/api",
                    "status": "confirmed",
                    "method": "POST",
                }
            ],
        )
        # User sees menu, types "back"
        with patch(
            "spring2shell.core.report_loader.interactive_exploitation_menu", return_value=None
        ):
            load_report_and_exploit(str(report))
        # Should not raise
