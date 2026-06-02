"""
Scan checkpoint/resume support for spring2shell.

Saves scan progress to a JSON checkpoint file after each target.
Allows resuming an interrupted scan from where it left off.

Usage:
    # At scan start:
    cp = Checkpoint(output_prefix)
    remaining = cp.get_remaining(all_targets)

    # After each target:
    cp.save_progress(target, findings)

    # Final save:
    cp.finalize()
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from spring2shell.utils.logging import log_event


class Checkpoint:
    """Manages scan progress checkpointing for resume support.

    Args:
        output_prefix: The scan output prefix (e.g. ``reports/scan``).
                       Checkpoint file is ``{prefix}.checkpoint.json``.
    """

    def __init__(self, output_prefix: str) -> None:
        self._path = Path(f"{output_prefix}.checkpoint.json")
        self._state: dict[str, Any] = self._load()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                log_event(
                    logging.INFO,
                    f"Checkpoint loaded: {len(data.get('scanned', []))} targets already done",
                    path=str(self._path),
                )
                return data
            except (json.JSONDecodeError, OSError) as exc:
                log_event(logging.WARNING, f"Could not read checkpoint file: {exc}")
        return {
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
            "scanned": [],
            "results": [],
        }

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._state["updated_at"] = datetime.now(tz=timezone.utc).isoformat()
        self._path.write_text(json.dumps(self._state, indent=2, ensure_ascii=False))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_resume(self) -> bool:
        """True if this checkpoint was loaded from an existing file."""
        return bool(self._state.get("scanned"))

    def get_remaining(self, all_targets: list[str]) -> list[str]:
        """Return targets that have not yet been scanned.

        Args:
            all_targets: Full list of scan targets.

        Returns:
            Subset of *all_targets* not yet in the checkpoint.
        """
        done = set(self._state.get("scanned", []))
        remaining = [t for t in all_targets if t not in done]
        if self.is_resume:
            log_event(
                logging.INFO,
                f"Resume: {len(done)} done, {len(remaining)} remaining",
            )
        return remaining

    def save_progress(self, target: str, findings: list[dict[str, Any]]) -> None:
        """Record completion of *target* and append its *findings*.

        Args:
            target:   The target URL that was just scanned.
            findings: Findings dict list from this target.
        """
        if target not in self._state["scanned"]:
            self._state["scanned"].append(target)
        self._state.setdefault("results", []).extend(findings)
        self._save()

    def get_all_results(self) -> list[dict[str, Any]]:
        """Return all findings accumulated so far (from checkpoint + current run)."""
        return list(self._state.get("results", []))

    def finalize(self) -> None:
        """Remove the checkpoint file after a successful completed scan."""
        if self._path.exists():
            self._path.unlink()
            log_event(logging.INFO, f"Checkpoint removed after successful scan: {self._path}")
